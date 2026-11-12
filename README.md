# Splatoon PC NEX server

The online server for the [Splatoon 1 PC port](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port): sign-in,
matchmaking, NAT test, friends and sign-up over HTTP. Matches themselves are peer-to-peer.
It replaces Nintendo's servers and contains or reads no Nintendo content.

The server is one Go binary (`cmd/splatoon-nex`). Full hosting guide: [docs/SERVEUR.md](docs/SERVEUR.md); Linux
scripts and systemd unit: [deploy/](deploy/README.md).

## Requirements

- Go, at the version in `go.mod` (to build). No other dependency to install.
- A machine reachable from the Internet, Windows or Linux.
- For the NAT test: **two different public IPs**. With one, set `"natcheck": false` (the game may then leave a session).
- For sign-up and friends: a domain and a TLS reverse proxy, for example Caddy with [deploy/Caddyfile](deploy/Caddyfile).

## Build

```
go build -trimpath -o splatoon-nex ./cmd/splatoon-nex
```

## Configure

Copy [deploy/server.example.json](deploy/server.example.json) to `server.json` and edit it. Every key is optional; an
unknown key is an error. A public server (the addresses are documentation addresses, use your own):

```json
{
  "mode": "public",
  "advertise": "203.0.113.10",
  "natcheck": true,
  "natcheck_addresses": ["203.0.113.10", "203.0.113.11"],
  "accounts_db": "accounts.sqlite3",
  "registration": "open",
  "registration_proxy": true,
  "min_client_version": "0.1.0",
  "integrity_mode": "log",
  "integrity_releases": { "0.1.5": ["<release_hash>"] }
}
```

`<release_hash>` is a placeholder: the server only accepts 64 lowercase hex digits there (see "Declare a hash").

| Key | Meaning |
|---|---|
| `mode` | `lab` (default, loopback only) or `public` |
| `listen`, `advertise` | address to bind (public default `0.0.0.0`) and the address players are told to reach; `advertise` is required when `listen` is a wildcard, and neither can be loopback in public mode |
| `auth_port`, `secure_port` | UDP 60000 and `auth_port + 1` by default |
| `natcheck`, `natcheck_addresses` | answer NAT checks, on these two public IPs (UDP 10025 and 10125 on each) |
| `accounts_db` | SQLite file of the accounts |
| `registration` | `closed` (default), `token` (needs `registration_token`) or `open` |
| `registration_port` | local HTTP port of sign-up, friends and admin (default `auth_port + 2`; none when registration is `closed`) |
| `registration_proxy` | the HTTP endpoint sits behind your reverse proxy |
| `admin_token` | token for the `ops` administration commands |
| `min_client_version` | oldest game version allowed to play, shown in `/health`; format `0.1.0` |
| `integrity_mode` | `off` (default), `log` or `enforce`, see below |
| `integrity_releases` | accepted releases: a version, then one or several release hashes |

The remaining keys are `registration_token`, `fill_timeout`, `random_session_key`, `natcheck_single_ip`,
`natcheck_same_socket`, `identities` and `identity_roots`. Check a file without starting anything:

```
./splatoon-nex --config server.json --check-config
```

**`server.json` holds `admin_token` and `registration_token`: never commit it.** `.gitignore` already excludes it,
the accounts databases and the logs.

## Run

```
./splatoon-nex --config server.json --log nexserver.log
```

On Linux keep it up with [deploy/splatoon-nex-go.service](deploy/splatoon-nex-go.service) (see [deploy/](deploy/README.md)).
Once the proxy runs, `https://your-domain.example/health` must answer.

## Ports to open

| Port | Use |
|---|---|
| UDP 60000, 60001 | game sign-in and secure server |
| UDP 10025, 10125 | NAT check, on **both** public IPs |
| TCP 80, 443 | reverse proxy (certificate, sign-up, friends) |

Never expose the local HTTP port (60002 by default): only the proxy reaches it.

## Integrity mode

The player's game sends its version and a hash of its code when it signs in. The server compares it with
`integrity_releases`:

- `off`: nothing is checked.
- `log`: unknown hashes are only logged (`integrity: ... refused proof`). Start here.
- `enforce`: a PC that has not proved a listed release in the last 12 hours is refused, in the HTTP sign-in (426) and
  in the NEX login. It needs at least one entry in `integrity_releases`.

It makes casual changes and old versions visible and refused. It cannot stop someone who copies the right hash:
moderation stays the real answer.

### Declare a hash

1. In the game repository, at the release's tag: `py -3 scripts/integrity.py --make`. It prints the `release_hash`
   (64 lowercase hex digits).
2. Add it to `server.json` under the release's version (a version may list several hashes):
   `"integrity_releases": { "0.1.5": ["<release_hash>"] }`.
3. Restart the server, watch the log, then switch `integrity_mode` to `enforce` once players have updated.

[deploy/set_integrity.py](deploy/set_integrity.py) makes the same change over SSH, with a dry run first.

## Moderation and accounts

```
./splatoon-nex accounts ...
./splatoon-nex ops ...
```

`accounts` works on the database (list, add, delete, ban, unban, bans, modlog, backup, restore); `ops` talks to the
running server with the admin token (metrics, sessions, bans, log, kick, ban, unban). Details:
[docs/SERVEUR.md](docs/SERVEUR.md).

## Test

```
go vet ./...
go test ./...
```

The deploy scripts have their own tests: `py -3 -m unittest discover -s deploy/tests`.

## Privacy

The server stores an account number, a derived key (never the password), the pseudo and creation and last-seen dates.
IP addresses are in the logs and, briefly, used for sign-up limits and bans. Tell your players.

## License

MPL 2.0, see `LICENSE.txt`. Third-party notices: `THIRD-PARTY-NOTICES.md`.
