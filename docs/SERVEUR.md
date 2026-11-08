# Run your own server

Français : [SERVEUR.fr.md](SERVEUR.fr.md).

The server in `tools/nexlab/` (Python) replaces Nintendo's servers for online play: sign-in, matchmaking and the NAT test.
It contains and reads no Nintendo content. This repository is enough to run one; the game itself lives in the
[port repository](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port).

## Steps

1. **Machine:** Windows or Linux, Python 3.12, a public IP. The NAT test needs **two different public IPs** (otherwise set `"natcheck": false`, and the game may leave the session).
2. **Install:** `py -3.12 -m pip install -r tools\nexlab\requirements.txt` (Linux: a venv, see [deploy/README.md](../deploy/README.md)).
3. **Configure:** copy `tools/nexlab/server.example.json` to `server.json` and edit it. For a public server:
   ```json
   {
     "mode": "public",
     "advertise": "203.0.113.10",
     "natcheck": true,
     "natcheck_addresses": ["203.0.113.10", "203.0.113.11"],
     "natcheck_same_socket": true,
     "accounts_db": "/var/lib/splatoon/accounts.sqlite3",
     "registration": "open",
     "registration_proxy": true,
     "registration_port": 60002,
     "min_client_version": "0.1.0"
   }
   ```
4. **Open the ports:** UDP 60000, 60001, 10025, 10125 (10025 and 10125 on **both** IPs), and TCP 80 and 443 for the HTTPS sign-up below. Never expose TCP 60002.
5. **HTTPS sign-up and friends:** point a domain (a free DuckDNS one works) to the server and run Caddy with [deploy/Caddyfile](../deploy/Caddyfile): `SPLATOON_DOMAIN=your-domain.example caddy run --config deploy/Caddyfile`. Caddy gets the certificate by itself. `/social/*` serves the friends feature (unique pseudos, who is online).
6. **Start:** `py -3.12 tools\nexlab\nexserver.py --config server.json`. On Linux keep it up with [deploy/splatoon-nex.service](../deploy/splatoon-nex.service). The log must show `mode=public`, `NAT check on ...` and `accounts: ...`.
7. **Point the players to it** (see the next section).
8. **Check:** `https://your-domain.example/health` must answer `{"ok": true, ...}`.

## Files that come from the port

The server alone does not make players use it. Three files live in the port repository (branch `SplatPc-ONLINE` for now), not here:

- [`scripts/server.public.txt`](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port/blob/SplatPc-ONLINE/scripts/server.public.txt): the address the game's launcher connects to. Put your own values (a local `scripts/server.txt` wins):
  ```
  server=203.0.113.10:60000
  nncs1=203.0.113.10
  nncs2=203.0.113.11
  register=https://your-domain.example/register
  ```
- [`scripts/integrity-manifest.txt`](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port/blob/SplatPc-ONLINE/scripts/integrity-manifest.txt): the hash of every code file of a game release.
- [`scripts/integrity.py`](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port/blob/SplatPc-ONLINE/scripts/integrity.py): `--make` rewrites the manifest and prints the release's `release_hash`; the game sends the same hash at sign-in. Put it in `integrity_releases` (below).

## Running it

```
py -3.12 -m tools.nexlab.accounts ban --pid 5eea2491 --reason "cheating"   # or --ip 203.0.113.7
py -3.12 -m tools.nexlab.accounts unban --pid 5eea2491
py -3.12 -m tools.nexlab.accounts backup backup.sqlite3                     # stop the server before restore
```

- **Old game versions:** `min_client_version` is published in `/health`; the launcher refuses to play online below it. Raise it after an update that breaks compatibility, then restart the server.
- **Game integrity:** the player's relay sends its version and a hash of the game's code when it signs in (`/social/session`). In `server.json`: `"integrity_mode": "log"` only logs unknown hashes; `"enforce"` refuses the sign-in (HTTP 426) **and** the NEX login of a PC that has not proved a listed release in the last 12 hours; `"integrity_releases": {"0.1.3": ["<release_hash>"]}` lists the accepted releases (a version may list several hashes). Start with `log`, check the log (`integrity: pid ... refused proof`), then switch to `enforce` once players have updated. `deploy/set_integrity.py` does this over SSH. It makes casual changes and old versions visible and refused; it cannot stop someone who copies the right hash, so moderation stays the real answer.
- **Moderation:** `py -3.12 tools/nexlab/ops.py --url ... --token <admin_token> ban --pid 5eea2491 --hours 24 --reason "insults"` bans at once (the player is disconnected, the session and integrity proof are dropped); `--hours` is optional (no value: for good); `unban`, `bans` and `log` (every ban, unban and kick, with date and reason) work the same way. An address ban (`--ip`) also stops a new account from the same address.
- **Updating the server:** [deploy/](../deploy/README.md) (backups, rehearsal, rollback).
- **Logs:** rotating, 8 MB x 3. Read them first when the game stops at a step.
- **Common problems:** `Address already in use` (port taken); the player quits after matchmaking (NAT test unreachable: check ports 10025/10125 and the two IPs); `RendezVous::InvalidUsername` (account not signed up yet, or banned).

## Taking over (Reprise)

The code, scripts and docs are all here. What the previous maintainer holds and **cannot be in this repository**; you create your own:

- the machine (VPS) and its public IPs, plus the SSH key to reach it;
- the domain (for example DuckDNS) and its token;
- `server.json`: the admin and registration tokens, created on the server;
- the accounts database (`accounts.sqlite3`) and its backups: players' accounts stay with the old server unless it is handed over;
- the key that signs the game's release tags, and the GitHub accounts and rights over the repositories.

Without the old database, a new server starts with no accounts: players sign up again.

## Privacy (what you store)

An account number, a derived key (never the password), the player's pseudo, creation and last-seen dates (who is online lives in memory only, for 30 seconds); IP addresses in the logs and, briefly, for sign-up limits and bans. Say so to your players.
