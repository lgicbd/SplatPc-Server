# Héberger son propre serveur

English: [SERVEUR.md](SERVEUR.md) (les exemples de configuration y sont).

Le serveur de `tools/nexlab/` (Python) remplace les serveurs de Nintendo pour le jeu en ligne : connexion, matchmaking et test NAT.
Il ne contient ni ne lit aucun contenu de Nintendo. Ce dépôt suffit à en faire tourner un ; le jeu est dans le
[dépôt du port](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port).

## Étapes

1. **Machine :** Windows ou Linux, Python 3.12, une IP publique. Le test NAT demande **deux IP publiques différentes** (sinon `"natcheck": false`, et le jeu peut quitter la session).
2. **Installer :** `py -3.12 -m pip install -r tools\nexlab\requirements.txt` (Linux : un venv, voir [deploy/README.md](../deploy/README.md)).
3. **Configurer :** copie `tools/nexlab/server.example.json` en `server.json` et adapte-le (exemple public dans [SERVEUR.md](SERVEUR.md)).
4. **Ouvrir les ports :** UDP 60000, 60001, 10025, 10125 (10025 et 10125 sur **les deux** IP), et TCP 80 et 443 pour l'inscription HTTPS. N'expose jamais le TCP 60002.
5. **Inscription et amis en HTTPS :** pointe un nom de domaine (un DuckDNS gratuit suffit) vers le serveur et lance Caddy avec [deploy/Caddyfile](../deploy/Caddyfile) : `SPLATOON_DOMAIN=ton-domaine caddy run --config deploy/Caddyfile`. Caddy obtient seul le certificat.
6. **Démarrer :** `py -3.12 tools\nexlab\nexserver.py --config server.json`. Sous Linux, [deploy/splatoon-nex.service](../deploy/splatoon-nex.service) le garde en marche. Le journal doit afficher `mode=public`, `NAT check on ...` et `accounts: ...`.
7. **Indiquer le serveur aux joueurs :** voir la section suivante.
8. **Vérifier :** `https://ton-domaine/health` doit répondre `{"ok": true, ...}`.

## Fichiers qui viennent du port

Trois fichiers sont dans le dépôt du port (branche `SplatPc-ONLINE` pour l'instant), pas ici :

- [`scripts/server.public.txt`](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port/blob/SplatPc-ONLINE/scripts/server.public.txt) : l'adresse à laquelle le lanceur du jeu se connecte (`server=`, `nncs1=`, `nncs2=`, `register=`). Un `scripts/server.txt` local est prioritaire.
- [`scripts/integrity-manifest.txt`](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port/blob/SplatPc-ONLINE/scripts/integrity-manifest.txt) : le hash de chaque fichier de code d'une version du jeu.
- [`scripts/integrity.py`](https://github.com/PC-PORTERS/SplatPC-Splatoon-Native-PC-Port/blob/SplatPc-ONLINE/scripts/integrity.py) : `--make` réécrit le manifeste et affiche le `release_hash` de la version ; le jeu envoie le même hash à la connexion. À mettre dans `integrity_releases`.

## Exploitation

- **Bannir / débannir / sauvegarder :** commandes `accounts ban`, `unban`, `backup` et `ops.py` décrites dans [SERVEUR.md](SERVEUR.md) (arrête le serveur avant une restauration).
- **Anciennes versions du jeu :** `min_client_version` est publié dans `/health` ; le lanceur refuse de jouer en ligne en dessous. Redémarre le serveur après l'avoir changé.
- **Intégrité du jeu :** le relais du joueur envoie sa version et un hash du code à la connexion. `"integrity_mode": "log"` note seulement les hash inconnus ; `"enforce"` refuse la connexion (HTTP 426) **et** le login NEX d'un PC qui n'a pas prouvé une version listée dans les 12 dernières heures ; `"integrity_releases": {"0.1.3": ["<release_hash>"]}` liste les versions acceptées. Commence par `log`, lis le journal (`integrity: pid ... refused proof`), puis passe à `enforce` quand les joueurs ont mis à jour (`deploy/set_integrity.py`). Cela n'arrête pas quelqu'un qui copie le bon hash : la modération reste la vraie réponse.
- **Modération :** `ops.py ban --pid ... --hours 24 --reason "..."` bannit tout de suite ; `--hours` est facultatif (sans valeur : définitif) ; `unban`, `bans`, `log` fonctionnent pareil. Un ban d'adresse (`--ip`) bloque aussi un nouveau compte depuis la même adresse.
- **Mettre le serveur à jour :** [deploy/](../deploy/README.md) (sauvegardes, répétition, retour arrière).
- **Journaux :** tournants, 8 Mo x 3. À lire en premier quand le jeu s'arrête à une étape.
- **Problèmes courants :** `Address already in use` (port pris) ; le joueur quitte après le matchmaking (test NAT injoignable : ports 10025/10125 et deux IP) ; `RendezVous::InvalidUsername` (compte pas encore inscrit, ou banni).

## Reprise

Le code, les scripts et la doc sont ici. Ce que détient le responsable actuel et qui **ne peut pas être dans ce dépôt** ; tu crées les tiens :

- la machine (VPS), ses IP publiques et la clé SSH pour y accéder ;
- le domaine (par exemple DuckDNS) et son jeton ;
- `server.json` : les jetons admin et d'inscription, créés sur le serveur ;
- la base des comptes (`accounts.sqlite3`) et ses sauvegardes : les comptes des joueurs restent sur l'ancien serveur sauf transmission ;
- la clé qui signe les tags de version du jeu, et les comptes GitHub et droits sur les dépôts.

Sans l'ancienne base, un nouveau serveur démarre sans comptes : les joueurs se réinscrivent.

## Vie privée

Un numéro de compte, une clé dérivée (jamais le mot de passe), le pseudo, les dates de création et de dernière connexion (qui est en ligne reste en mémoire, 30 secondes) ; des adresses IP dans les journaux et, brièvement, pour les limites d'inscription et les bannissements. Dis-le à tes joueurs.
