# Deploy

Generic scripts to run the server on a Linux machine you own. Nothing here knows your address or key: pass them as arguments.

| File | Purpose |
|---|---|
| `deploy_go.py` | move a Python server to the Go binary over SSH: parallel run, cutover, rollback |
| `deploy_server.py` | upload the Python server code over SSH with backups, restart, verify, `--rollback` |
| `set_integrity.py` | set `integrity_mode` and the accepted release hashes in `server.json` |
| `rehearsal.py` | try the move locally on the old Python code and a database it made |
| `Caddyfile` | HTTPS in front of sign-up, friends and `/health` |
| `splatoon-nex-go.service` | systemd unit of the Go server |
| `splatoon-nex.service` | systemd unit of the Python server |

## First install (Linux, as root)

```
useradd --system --home /opt/splatoon splatoon
mkdir -p /opt/splatoon/tools /var/lib/splatoon /var/log/splatoon
chown splatoon: /var/lib/splatoon /var/log/splatoon
python3.12 -m venv /opt/splatoon/venv
cp -r tools/nexlab /opt/splatoon/tools/          # then: /opt/splatoon/venv/bin/pip install -r tools/nexlab/requirements.txt
cp tools/nexlab/server.example.json /opt/splatoon/server.json   # edit it, see docs/SERVEUR.md
chown splatoon: /opt/splatoon/server.json && chmod 600 /opt/splatoon/server.json
cp deploy/splatoon-nex.service /etc/systemd/system/ && systemctl enable --now splatoon-nex
```

## Update

```
py -3 deploy/rehearsal.py --old-rev <revision running now>
py -3 deploy/deploy_server.py --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example           # dry run
py -3 deploy/deploy_server.py --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
```

The restart drops running matches: update when nobody plays.

## Move from Python to Go

```
py -3.12 deploy/rehearsal.py --old-rev <revision running now>
py -3 deploy/deploy_go.py parallel --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example           # dry run
py -3 deploy/deploy_go.py parallel --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
py -3 deploy/deploy_go.py stop-parallel --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
py -3 deploy/deploy_go.py cutover --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
py -3 deploy/deploy_go.py rollback --host root@SERVER --key ~/.ssh/KEY --domain your-domain.example --apply
```

`parallel` runs Go next to Python on UDP 60100 and 60101, with a copy of the database and no NAT check. Point a test game
at it with a local `scripts/server.txt`, and reach its HTTP endpoint (friends, integrity proof) through the SSH tunnel it
prints. `cutover` drops running matches. After it, pass `--service splatoon-nex-go` to `set_integrity.py`: a guard keeps the
Python unit from starting while Go is live, so restarting it does nothing.

### Tried on a WSL Ubuntu-24.04 (08/11)

First install as above (plus `apt install openssh-server python3-venv`; WSL needs `systemd=true` in `/etc/wsl.conf`, and a
process kept running, e.g. `wsl -u root -- sleep infinity`, or the VM stops and SSH with it). With the Python unit running:
`parallel`, `stop-parallel`, `cutover`, `set_integrity.py ... --service splatoon-nex-go --apply` and `rollback` all passed,
`server.json` stayed owned by `splatoon` with mode 600, Go came back alone after a reboot (Python unit disabled and guarded).
`server.json` must be plain UTF-8 without a BOM: the script reads it as JSON.
