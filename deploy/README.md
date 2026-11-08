# Deploy

Generic scripts to run the server on a Linux machine you own. Nothing here knows your address or key: pass them as arguments.

| File | Purpose |
|---|---|
| `deploy_server.py` | upload the server code over SSH with backups, restart, verify, `--rollback` |
| `set_integrity.py` | set `integrity_mode` and the accepted release hashes in `server.json` |
| `rehearsal.py` | try an update locally on a copy of the old code and database first |
| `Caddyfile` | HTTPS in front of sign-up, friends and `/health` |
| `splatoon-nex.service` | systemd unit |

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
