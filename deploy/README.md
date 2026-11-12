# Deploy

Generic scripts to run the server on a Linux machine you own. Nothing here knows your address or key: pass them as arguments.

| File | Purpose |
|---|---|
| `set_integrity.py` | set `integrity_mode` and the accepted release hashes in `server.json`, checked by the binary, then restart |
| `go_test_env.py` | a test server next to the live one (own unit, ports and database copy, integrity `log`) |
| `go_server.py`, `remote.py` | shared by the scripts: paths on the server, SSH, build of the Linux binary |
| `Caddyfile` | HTTPS in front of sign-up, friends and `/health` |
| `splatoon-nex-go.service` | systemd unit of the server |
| `server.example.json` | configuration to start from, see [docs/SERVEUR.md](../docs/SERVEUR.md) |

## First install (Linux, as root)

Build the binary on your PC (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o build/linux/splatoon-nex ./cmd/splatoon-nex`),
copy it and this folder to the server, then:

```
useradd --system --home /opt/splatoon splatoon
mkdir -p /opt/splatoon/go /var/lib/splatoon /var/log/splatoon
chown splatoon: /var/lib/splatoon /var/log/splatoon
install -o splatoon -g splatoon -m 755 splatoon-nex /opt/splatoon/go/splatoon-nex
cp deploy/server.example.json /opt/splatoon/server.json        # edit it, see docs/SERVEUR.md
chown splatoon: /opt/splatoon/server.json && chmod 600 /opt/splatoon/server.json
ln -s ../server.json /opt/splatoon/go/server.json && chown -h splatoon: /opt/splatoon/go/server.json
runuser -u splatoon -- /opt/splatoon/go/splatoon-nex --config /opt/splatoon/go/server.json --check-config
cp deploy/splatoon-nex-go.service /etc/systemd/system/ && systemctl enable --now splatoon-nex-go
```

`server.json` must be plain UTF-8 without a BOM. Set `accounts_db` to a file in `/var/lib/splatoon` (the unit can only
write there and in `/var/log/splatoon`).

## Integrity and minimum version

```
py -3 deploy/set_integrity.py --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example enforce 0.1.5=<hash>           # dry run
py -3 deploy/set_integrity.py --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example enforce 0.1.5=<hash> --apply
```

The restart drops running matches: change it when nobody plays. The script prints the undo command.

## Test server

```
py -3 deploy/go_test_env.py install --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example           # dry run
py -3 deploy/go_test_env.py install --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
py -3 deploy/go_test_env.py stop --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
```

It runs on UDP 60100 and 60101 with a copy of the database and no NAT check. Point a test game at it with a local
`scripts/server.txt`, and reach its HTTP endpoint through the SSH tunnel it prints. The database copy uses `python3` on the
server (`--remote-python` to choose another).

## Tests

```
py -3 -m unittest discover -s deploy/tests -v
```
