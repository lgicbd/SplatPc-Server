# Splatoon PC NEX server

Server for the online mode of the [Splatoon 1 PC port](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port):
sign-in, matchmaking and NAT test. Matches are peer-to-peer.

## Run

```
py -3.12 -m pip install -r tools\nexlab\requirements.txt
copy tools\nexlab\server.example.json server.json
py -3.12 tools\nexlab\nexserver.py --config server.json
```

Full guide: [docs/SERVEUR.md](docs/SERVEUR.md).

## Test

```
py -3.12 -m unittest discover -s tools/tests -p "test_*.py"
```

## Secrets

Never commit `server.json` (admin and registration tokens) or `*.sqlite3` (accounts). Both are in `.gitignore`.

## License

MPL 2.0, see `LICENSE.txt`.
