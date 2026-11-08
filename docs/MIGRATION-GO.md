# Python to Go migration

Working plan, removed with the Python server (lot 7).

| Lot | Content | State |
|-----|---------|-------|
| 0 | Go module, reference vectors, black-box harness | done |
| 1 | Config, accounts, friends, HTTP, `accounts` and `ops` commands | done |
| 2 | PRUDP, RMC, Kerberos, auth and secure servers | done |
| 3 | Matchmaking, NAT check, notifications, probes | done |
| 4 | Integrity and moderation on the NEX path, limits, load | to do |
| 5 | Real-game test, deployment rehearsal | to do |
| 6 | Parallel run on the VPS, then cutover (rollback: restart Python, same database) | to do |
| 7 | Remove Python, short README, secret scan of the history, go public | to do |

## How behaviour is checked

- **Black box:** `tools/tests/test_go_interop.py` starts the Go binary and drives it with
  NintendoClients, the same client as the Python tests. Run it with `SPLATOON_NEX_SERVER=python`
  to check the expectations against the reference. Set `NEXLAB_LOAD_TEST=1` to add the 100-player
  load test.
- **Go tests:** cases that need the server's internals are ported next to the code, with
  `FuzzDecode` (`internal/prudp`) and `FuzzRequests` (`internal/matchmake`).
- **Only the real game (lot 5) proves interoperability:** NintendoClients is not the game.
- **Vectors:** `tools/tests/vectors/generate_vectors.py` writes `testdata/vectors` from the Python
  library, with invented values.

## Deliberate differences from Python

- `IsBanned` canonicalizes the address, so an IPv6 ban covers its /64 (Python compared the raw
  address and missed it).
- A kick applies at once instead of waiting for the janitor.
- A handler that cannot decode its parameters answers `Core::Exception`.
- A failed restore leaves the database untouched: the backup is copied aside first.
- Friend lists that are not JSON arrays are ignored (Python iterated strings and objects).
- A connection replaced by a new `Register` closing late no longer erases the session: a cut
  connection times out long after the player came back, and only the live connections count.

## Not ported

- `tools/nexlab/register.py` is a client tool, not part of the server, so its URL guard tests stay in
  Python until lot 7 decides its fate.
