# Keryx avec Docker : mode d'emploi

Référence complète (durcissement ANSSI, matrice des flux, PDIS, limites) : [`docs/deploiement-docker.md`](../../docs/deploiement-docker.md). Décision : [ADR-0023](../../docs/adr/0023-deploiement-par-conteneurs.md).

**À qui ce kit convient** : essais, démonstrations, petit SOC non qualifié. Tout tourne sur une seule machine : ce n'est pas le cloisonnement en zones qu'exige PDIS (voir « Ce déploiement et PDIS » dans la référence).

## Installer

Il faut : Docker Engine et `docker compose` 2.24 ou plus récent, les ports 80 et 443 libres, et pour une vraie mise en service un nom de domaine qui pointe vers la machine. Mémoire relevée à l'essai, au repos : 130 Mo pour Keryx, sa base et le reverse proxy ; 1 Go de plus pour ClamAV, 0,5 Go pour Keycloak (plafonds par conteneur dans `docker-compose.yml`).

```sh
cd deploy/docker
./install.sh
```

Le script pose quatre questions, puis construit, démarre, attend que Keryx réponde et crée le premier compte Admin.

| Question | Réponses |
|---|---|
| Mode HTTPS | `acme` : certificat obtenu et renouvelé automatiquement (il faut donner l'adresse de l'annuaire ACME de l'autorité choisie, il n'y a pas d'autorité par défaut). `fourni` : votre certificat, déposé avant dans `certs/keryx.crt` (chaîne complète) et `certs/keryx.key`. `local` : essai sur cette machine, certificat interne. |
| Nom de domaine | Celui tapé dans le navigateur et dans Wazuh. `localhost` en mode `local`. |
| Profils | Aucun, ou une liste parmi `antivirus` (ClamAV), `sso` (Keycloak), `objets` (Garage), `sauvegarde` (sauvegarde chaque jour). |
| Sorties réseau de Keryx | `non` par défaut. `oui` s'il doit envoyer des courriels, horodater, lire un indexeur Wazuh, exporter son audit en syslog ou interroger VirusTotal. |

Sans question, par exemple pour un essai local sur d'autres ports :

```sh
KERYX_NON_INTERACTIF=1 KERYX_HTTPS_MODE=local KERYX_HTTP_PORT=8080 KERYX_HTTPS_PORT=8443 \
  KERYX_PROFILES=antivirus,sauvegarde ./install.sh
```

À la fin, le script affiche **une seule fois** l'identifiant, le mot de passe temporaire et le code d'activation du compte Admin, puis le bloc `<integration>` à coller dans Wazuh.

## Sauvegarder, tout de suite

1. **`deploy/docker/.env`** : il contient `KERYX_SECRET_KEY`, la clé maîtresse. Si elle est perdue, sont perdus sans recours les secrets TOTP de tous les comptes, les clés VirusTotal des analystes, les comptes de lecture des indexeurs Wazuh, les pièces du stockage objet et toutes les sauvegardes. Le copier hors de la machine, à part des sauvegardes.
2. **Les données** : le profil `sauvegarde` écrit chaque jour une archive chiffrée dans le volume `sauvegardes` (les 14 dernières sont gardées). Ce volume est sur la même machine : le copier ailleurs.
   ```sh
   docker compose cp sauvegarde:/sauvegardes ./copie-des-sauvegardes
   ```
   Sans ce profil : `docker compose exec -e TMPDIR=/data keryx python -m keryx.cli backup /data/keryx.kxb`, puis `docker compose cp keryx:/data/keryx.kxb .` et `docker compose exec keryx rm /data/keryx.kxb`.
3. Avec le profil `objets`, les pièces ne sont plus dans l'archive : sauvegarder aussi les volumes `garage_meta` et `garage_data`.

## Au quotidien

Les commandes se lancent dans `deploy/docker`.

| Besoin | Commande |
|---|---|
| État | `docker compose ps` |
| Journaux | `docker compose logs -f keryx` (ou `caddy`, `postgres`…) |
| Commande d'administration de Keryx | `docker compose exec keryx python -m keryx.cli verify-audit` |
| Changer un réglage | modifier `.env`, puis `docker compose up -d` |
| Ajouter un profil | l'ajouter à `COMPOSE_PROFILES` dans `.env`, puis `./install.sh` |
| Mettre à jour Keryx | `git pull`, puis `./install.sh` (reconstruit, applique les migrations au démarrage) |
| Arrêter | `./uninstall.sh` : conteneurs et réseaux retirés, **volumes et `.env` conservés** |
| Redémarrer | `docker compose up -d` |
| Tout supprimer | `./uninstall.sh --purger` : demande de taper le nom du projet, puis supprime les volumes |

Deux pièges :

- Ne pas laisser de variable vide dans `.env` (`KERYX_SMTP_PORT=` empêche Keryx de démarrer) : commenter la ligne.
- Ne pas exporter de variable `KERYX_…` dans le terminal : pour `docker compose`, elle l'emporte sur `.env`. `install.sh` s'en protège, pas une commande `docker compose` tapée à la main.

## Fichiers

| Fichier | Rôle |
|---|---|
| `docker-compose.yml` | Les services, leurs réseaux, leur durcissement |
| `install.sh`, `uninstall.sh` | Installation relançable ; arrêt |
| `.env.example` | Toutes les variables, commentées (le vrai `.env` est écrit par `install.sh`) |
| `caddy/` | Reverse proxy : `Caddyfile`, un fichier par mode HTTPS dans `tls/`, le site de Keycloak |
| `certs/` | Mode `fourni` : `keryx.crt`, `keryx.key` (et `sso.crt`, `sso.key`, `ca.crt` si l'autorité est privée) |
| `confiance/` | Autorités de certification que Keryx doit reconnaître en plus de celles du système |
| `keycloak/` | Image de Keycloak et realms `soc` et `clients` importés au premier démarrage |
| `garage/` | Image et configuration de Garage |
| `sauvegarde.sh` | Boucle du profil `sauvegarde` |
