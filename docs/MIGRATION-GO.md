# Python to Go migration

Working plan, removed with the Python server (lot 7).

| Lot | Content | State |
|-----|---------|-------|
| 0 | Go module, reference vectors, black-box harness | done |
| 1 | Config, accounts, friends, HTTP, `accounts` and `ops` commands | done |
| 2 | PRUDP, RMC, Kerberos, auth and secure servers | in progress |
| 3 | Matchmaking, NAT check, notifications, probes | to do |
| 4 | Integrity and moderation on the NEX path, limits, load | to do |
| 5 | Real-game test, deployment rehearsal | to do |
| 6 | Parallel run on the VPS, then cutover (rollback: restart Python, same database) | to do |
| 7 | Remove Python, short README, secret scan of the history, go public | to do |

## How behaviour is checked

- **Black box:** `tools/tests/test_go_interop.py` starts the Go binary and drives it with
  NintendoClients, the same client as the Python tests. Run it with `SPLATOON_NEX_SERVER=python`
  to check the expectations against the reference.
- **Go tests:** cases that need the server's internals are ported next to the code.
- **Vectors:** `tools/tests/vectors/generate_vectors.py` writes `testdata/vectors` from the Python
  library, with invented values.

## Deliberate differences from Python

- `IsBanned` canonicalizes the address, so an IPv6 ban covers its /64 (Python compared the raw
  address and missed it).
- A kick applies at once instead of waiting for the janitor.
- A handler that cannot decode its parameters answers `Core::Exception`.
- A failed restore leaves the database untouched: the backup is copied aside first.
- Friend lists that are not JSON arrays are ignored (Python iterated strings and objects).
