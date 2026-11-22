# Déploiement par conteneurs (Docker) : référence

*Kit : `deploy/docker/`. Mode d'emploi court : `deploy/docker/README.md`. Décision : ADR-0023. État au 22/11/2026.*

**Ce que c'est** : un fichier `docker-compose.yml`, un conteneur par service, des profils facultatifs, un script d'installation relançable. **Ce que ce n'est pas** : une architecture qualifiable PDIS. Tout tourne sur une machine ; la section 6 dit précisément ce qui manque et décrit la cible.

**Essayé pour de bon** le 22/11/2026 sur une machine Linux (Docker 29.9.3, compose 5.7.0, constructeur classique sans BuildKit) : construction, installation en mode `local`, tous les profils, puis les contrôles de la section 8. **Pas essayé** : le mode `acme` (il faut un nom de domaine public), le mode `fourni` avec un vrai certificat, un vrai manager Wazuh, les réglages du démon Docker de la section 3 (`userns-remap`, `bridge: none`, pilote de journaux).

## 1. Services, images, profils

| Service | Profil | Image | Utilisateur | Écrit dans |
|---|---|---|---|---|
| `caddy` | toujours | `caddy:2.11.9-alpine`, épinglée par empreinte | celui qui installe (jamais root) | volume `caddy_data`, tmpfs |
| `keryx` | toujours | construite par le `Dockerfile` du dépôt | 10001 | volume `keryx_data` (`/data`), tmpfs `/tmp` |
| `postgres` | toujours | `postgres:16.16-bookworm`, épinglée par empreinte | 999 (`postgres`) | volume `postgres_data`, tmpfs |
| `clamav` | `antivirus` | `clamav/clamav:1.4.7`, épinglée par empreinte | 100 (`clamav`) | volume `clamav_data`, tmpfs |
| `keycloak` | `sso` | `deploy/docker/keycloak/Dockerfile` sur `quay.io/keycloak/keycloak:26.8.2` épinglée | 1000 (`keycloak`) | tmpfs seulement |
| `keycloak-db` | `sso` | `postgres:16.16-bookworm`, épinglée | 999 | volume `keycloak_db_data`, tmpfs |
| `garage` | `objets` | `deploy/docker/garage/Dockerfile` sur `dxflrs/garage:v1.3.1` épinglée | 10002 | volumes `garage_meta`, `garage_data` |
| `sauvegarde` | `sauvegarde` | la même que `keryx` | 10001 | volume `sauvegardes` |

Deux images sont reconstruites, pour une raison précise chacune. Keycloak : sa phase de construction (`kc.sh build`) est faite dans l'image, sinon il réécrit `/opt/keycloak/lib/quarkus` à chaque démarrage et ne supporte pas une racine en lecture seule. Garage : l'image officielle ne contient que le binaire ; la nôtre ajoute les deux dossiers de données au nom d'un utilisateur sans privilège, pour que les volumes montés dessus lui appartiennent sans `chown` à l'exécution. Les images de base du `Dockerfile` de Keryx (`node:22-slim`, `python:3.12-slim`) ne sont pas épinglées par empreinte : à faire avant une mise en production (voir section 7).

**Où Keryx écrit** (vérifié en lecture seule) : `/data` (pièces, stockage `disk`), `/tmp` (corps des requêtes en cours de réception, archive de sauvegarde en préparation), et rien d'autre. Le `Dockerfile` crée aussi `/sauvegardes` au nom de l'utilisateur 10001 : c'est le point de montage du volume du profil `sauvegarde`.

**Variables** : toutes dans `deploy/docker/.env`, écrites par `install.sh`, décrites dans `.env.example`. Les variables de `keryx/config.py` qui ne servent qu'aux essais ne sont volontairement pas transmises au conteneur : `KERYX_AUTO_CREATE_SCHEMA`, `KERYX_OIDC_ALLOW_HTTP`, `KERYX_VIRUSTOTAL_URL`, `KERYX_VIRUSTOTAL_ALLOW_LOOPBACK`, `KERYX_WEB_DIST`. `KERYX_COOKIE_SECURE` est fixé à `true`.

**Secrets** : dans `.env` (mode 600, jamais commité, exclu du contexte de construction par `.dockerignore`), transmis par l'environnement des conteneurs. Les « secrets » de compose ne sont pas utilisés, et ce n'est pas un oubli : Keryx ne lit ses secrets que dans son environnement (`keryx/config.py`), donc le mot de passe de la base y figure de toute façon ; et compose refuse un secret tiré d'une variable sur un conteneur à racine en lecture seule (« `file` is the sole supported option », constaté), tandis qu'un secret tiré d'un fichier ignore `uid`, `gid` et `mode` hors Swarm, ce qui le rend illisible pour un conteneur sans root ni capability. Entre la lecture seule sans privilège et les fichiers de secrets, le kit garde la première. Conséquence : quiconque peut lancer `docker inspect` lit les secrets. L'accès au démon Docker vaut déjà les droits root sur la machine.

## 2. HTTPS

Caddy termine TLS (1.2 au minimum, 1.3 préféré : TLS 1.0 et 1.1 refusés, constaté), ajoute `Strict-Transport-Security`, redirige HTTP vers HTTPS, écrit `X-Forwarded-For`, `-Proto` et `-Host` en écartant ceux qu'un client aurait envoyés, et borne la taille des requêtes avec les mêmes valeurs que Keryx (2 Mio ; 21 Mio pour le dépôt d'une pièce ; 81 Mio pour le référentiel ATT&CK). Keryx ne croit ces en-têtes que venant de l'adresse de Caddy (`FORWARDED_ALLOW_IPS`, jamais `*`).

| `KERYX_HTTPS_MODE` | Certificat | À fournir |
|---|---|---|
| `acme` | obtenu et renouvelé par Caddy auprès d'une autorité ACME | `KERYX_ACME_CA` (adresse de l'annuaire), ports 80 et 443 joignables par l'autorité ; `KERYX_ACME_EMAIL`, `KERYX_ACME_EAB_KID` et `KERYX_ACME_EAB_HMAC` selon l'autorité |
| `fourni` | le vôtre | `certs/keryx.crt` (chaîne complète, PEM) et `certs/keryx.key` ; avec le profil `sso`, `certs/sso.crt` et `certs/sso.key` ; si l'autorité est privée, son certificat dans `certs/ca.crt` |
| `local` | signé par l'autorité interne de Caddy | rien. Essai sur une machine : les navigateurs ne connaissent pas cette autorité |

**Le mode `acme` n'a pas d'autorité par défaut, exprès.** Sans réglage, Caddy s'adresse à Let's Encrypt, exploité aux États-Unis ; la règle du projet est « aucune dépendance à un service hors de l'Union européenne » sans décision écrite (ADR-0022 en est une). `install.sh` exige donc `KERYX_ACME_CA`. Choisir Let's Encrypt (`https://acme-v02.api.letsencrypt.org/directory`, adresse non revérifiée ici) est possible : c'est une dérogation à consigner, comme VirusTotal. Ce que l'autorité apprend : le nom de domaine, l'adresse de la machine, les dates d'émission ; le certificat est publié dans les journaux de transparence. Aucune adresse d'autorité de l'UE n'est proposée ici, faute d'en avoir vérifié une : la prendre dans la documentation de l'autorité retenue. En cas de doute, le mode `fourni` ne dépend d'aucun service.

Changer de certificat en mode `fourni` : remplacer les fichiers, puis `docker compose restart caddy` (Caddy ne lit ces fichiers qu'au démarrage ; non essayé avec un vrai certificat).

**Autorité privée** (modes `local` et `fourni` avec autorité interne) : deux conséquences. Le manager Wazuh vérifie le certificat de Keryx : lui donner le certificat de l'autorité par `KERYX_CA_BUNDLE` (variable du script d'intégration). Et avec le profil `sso`, Keryx joint Keycloak par son adresse publique, donc à travers Caddy : `install.sh` écrit `confiance/ca-bundle.pem` (autorités du système suivies de l'autorité privée) et règle `KERYX_CA_BUNDLE` dans `.env`.

## 3. Durcissement : fiche ANSSI-FT-082

Fiche technique « Recommandations de sécurité relatives aux déploiements de conteneur Docker », ANSSI-FT-082, version 1.0 du 23/09/2020, lue en entier. Son périmètre : « le Docker daemon et la gestion des images Docker sont hors périmètre de l'étude ». Les intitulés ci-dessous sont ceux de la fiche. « Compose » : appliqué dans `docker-compose.yml` à **chaque** service et relevé par `docker inspect` sur les huit conteneurs en marche. « Hôte » : à régler sur le démon Docker ou le système, **non fait par le kit et non essayé**.

| N° | Intitulé | Où | Ce qui est fait, ou la raison |
|---|---|---|---|
| R1 | Isoler les systèmes sensibles de fichiers de l'hôte | Compose | Aucun `privileged`. Aucun montage de `/`, `/dev`, `/proc`, `/sys`. Le socket Docker n'est monté nulle part. Seuls montages de l'hôte : des fichiers de configuration du kit, en lecture seule |
| R2 | Restreindre l'accès aux périphériques de l'hôte | Non applicable | Aucun service n'a besoin d'un périphérique : aucun `devices` |
| R3 | Interdire la connexion du conteneur au réseau bridge docker0 | Compose + **Hôte** | Aucun service n'est sur `docker0` : chacun n'est relié qu'aux réseaux dédiés du projet. Le réglage du démon (`"bridge": "none"` dans `/etc/docker/daemon.json`) reste à faire sur l'hôte. Attention : la construction des images télécharge des paquets ; avec ce réglage, construire avant de l'activer, ou ailleurs (section 7) |
| R4 | Isoler l'interface réseau de l'hôte | Compose | Aucun `network_mode: host` |
| R5 | Créer un réseau dédié pour chaque connexion | Compose | Dix réseaux, un par connexion (section 4). Huit sont `internal` : sans route vers l'extérieur ni vers l'hôte |
| R6 | Dédier des namespaces PID, IPC et UTS pour chaque conteneur | Compose | Aucun `pid`, `ipc` ni `uts` partagé |
| R7 | Dédier un namespace USER ID pour chaque conteneur | **Hôte** | `"userns-remap": "default"` dans `daemon.json`. Non essayé. Effet à prévoir : les identifiants des conteneurs sont décalés, donc les fichiers de `certs/` et `confiance/` doivent être lisibles par l'identifiant décalé, et les volumes existants changent de propriétaire (à faire avant la première installation). En attendant, aucun conteneur ne tourne sous root, ce qui limite ce que R7 cherche à éviter |
| R7+ | Restreindre la création des Namespace USER ID à l'utilisateur root | **Hôte** | `kernel.unprivileged_userns_clone=0` sur un système à base Debian |
| R7- | Restreindre le partage du Namespace USER ID de l'hôte | Non applicable | Aucun service ne demande `userns_mode: host` |
| R8 | Interdire l'utilisation des capabilities | Compose | `cap_drop: [ALL]` partout, **aucun** `cap_add`. Caddy écoute sur 80 et 443 sans `CAP_NET_BIND_SERVICE` : Docker ouvre les ports bas aux conteneurs (`net.ipv4.ip_unprivileged_port_start=0` dans leur espace réseau). PostgreSQL et ClamAV démarrent directement sous leur utilisateur, sans le passage par root de leur image. `no-new-privileges` partout |
| R8- | Limiter l'utilisation des capabilities | Sans objet | R8 est tenu, la variante moins stricte ne sert pas |
| R9 | Dédier les Control groups pour chaque conteneur | Compose | Aucun `cgroup_parent` |
| R10 | Limiter l'utilisation de la mémoire de l'hôte pour chaque conteneur | Compose | `mem_limit` et `memswap_limit` égaux (aucune mémoire d'échange en plus) sur chaque service |
| R11 | Limiter l'utilisation du CPU de l'hôte pour chaque conteneur | Compose | `cpus` sur chaque service ; en plus, `pids_limit` |
| R12 | Restreindre en lecture le système de fichiers racine de chaque conteneur | Compose | `read_only: true` sur les huit services. R12- et R12-- (variantes moins strictes) ne servent donc pas |
| R13 | Créer un système de stockage pour les données non persistantes | Compose | `tmpfs` avec taille et mode pour chaque dossier temporaire, tous en `noexec,nosuid,nodev` |
| R14 | Créer un système de stockage pour les données persistantes ou partagées | Compose + **Hôte** | Volumes nommés ; ce qu'un conteneur ne doit pas modifier est monté en lecture seule (configuration, certificats, pièces vues par `sauvegarde`). **Écart** : la fiche demande « une limitation spécifiée de l'espace disque » ; un volume local de Docker n'en a pas. À régler sur l'hôte : partition dédiée à `/var/lib/docker/volumes`, ou quotas du système de fichiers |
| R15 | Restreindre l'accès aux répertoires et aux fichiers sensibles | Compose | Seul fichier sensible partagé avec l'hôte : la clé du certificat (`certs/`), en lecture seule, pour le seul conteneur `caddy` |
| R16 | Exporter les journaux avec Docker | **Hôte** | Tous les services journalisent sur la sortie standard ; compose borne les fichiers (`json-file`, 5 × 10 Mo). L'export « vers un serveur centralisé » n'est pas fait : soit collecter ces fichiers par l'agent Wazuh ou le syslog de l'hôte, soit remplacer le pilote dans le bloc `x-durci` de `docker-compose.yml` (un seul endroit) par `syslog`, `gelf` ou `journald` avec ses options |
| R16- | Exporter les journaux depuis l'intérieur du conteneur | Partiel | Keryx envoie son journal d'audit en syslog RFC 5424 (`KERYX_SYSLOG_HOST`), si la sortie est ouverte. Les autres services n'exportent rien eux-mêmes |

La fiche rappelle aussi ses risques résiduels : le démon Docker tourne sous root, et l'hôte doit être durci selon le guide ANSSI de configuration d'un système GNU/Linux. Rien de cela n'est traité par le kit.

## 4. Réseaux et matrice des flux

*PDIS IV.3.8.d demande une « matrice des flux de référence » et une « politique de filtrage associée, n'autorisant que les flux strictement nécessaires ». Voici celle du kit. Elle ne remplace pas celle du prestataire, qui couvre tout son système d'information.*

| Réseau Docker | Relie | `internal` |
|---|---|---|
| `entree` | hôte ↔ `caddy` (ports publiés ; sortie de Caddy vers l'autorité ACME) | non |
| `proxy-keryx` | `caddy` ↔ `keryx` (sous-réseau fixe) | oui |
| `proxy-keycloak` | `caddy` ↔ `keycloak` (sous-réseau fixe) | oui |
| `keryx-postgres` | `keryx` ↔ `postgres` | oui |
| `sauvegarde-postgres` | `sauvegarde` ↔ `postgres` | oui |
| `keryx-clamav` | `keryx` ↔ `clamav` | oui |
| `keryx-garage` | `keryx` ↔ `garage` | oui |
| `keycloak-postgres` | `keycloak` ↔ `keycloak-db` | oui |
| `keryx-sortie` | `keryx` → extérieur | **oui par défaut** ; `KERYX_SORTIE_FERMEE=false` l'ouvre |
| `clamav-sortie` | `clamav` → extérieur (signatures) | non ; `KERYX_CLAMAV_SORTIE_FERMEE=true` le ferme |

| N° | Source | Destination | Port | Protocole | Réseau | Quand |
|---|---|---|---|---|---|---|
| 1 | Navigateurs (équipe, Admin, clients) | `caddy` | 443/tcp | HTTPS | `entree` | toujours |
| 2 | Manager Wazuh | `caddy` | 443/tcp | HTTPS, clé d'API, `POST /api/v1/ingest/wazuh` | `entree` | toujours |
| 3 | Tout client | `caddy` | 80/tcp | HTTP : redirection vers HTTPS, défi ACME | `entree` | toujours |
| 4 | `caddy` | `keryx` | 8000/tcp | HTTP | `proxy-keryx` | toujours |
| 5 | `keryx` | `postgres` | 5432/tcp | PostgreSQL, mot de passe SCRAM | `keryx-postgres` | toujours |
| 6 | `caddy` | autorité ACME | 443/tcp | HTTPS | `entree` | mode `acme` |
| 7 | `keryx` | `clamav` | 3310/tcp | clamd | `keryx-clamav` | profil `antivirus` |
| 8 | `clamav` | `database.clamav.net` | 443/tcp | HTTPS (téléchargement seulement) | `clamav-sortie` | profil `antivirus` |
| 9 | Navigateurs | `caddy` (nom de Keycloak) | 443/tcp | HTTPS | `entree` | profil `sso` |
| 10 | `caddy` | `keycloak` | 8080/tcp | HTTP | `proxy-keycloak` | profil `sso` |
| 11 | `keryx` | `caddy` (nom de Keycloak) | 443/tcp | HTTPS : découverte, jeton, clés | `proxy-keryx` | profil `sso` |
| 12 | `keycloak` | `keycloak-db` | 5432/tcp | PostgreSQL | `keycloak-postgres` | profil `sso` |
| 13 | `keryx` | `garage` | 3900/tcp | S3 sur HTTP, requêtes signées, objets déjà chiffrés | `keryx-garage` | profil `objets` |
| 14 | `sauvegarde` | `postgres` | 5432/tcp | PostgreSQL (`pg_dump`) | `sauvegarde-postgres` | profil `sauvegarde` |
| 15 | `keryx` | relais SMTP | 587 ou 465/tcp | SMTP + TLS | `keryx-sortie` | sortie ouverte, SMTP réglé |
| 16 | `keryx` | autorité d'horodatage | 443/tcp | HTTPS (RFC 3161) | `keryx-sortie` | sortie ouverte, `KERYX_TSA_URL` |
| 17 | `keryx` | indexeur Wazuh d'un client | 9200/tcp | HTTPS, lecture seule | `keryx-sortie` | sortie ouverte, réglé par client |
| 18 | `keryx` | manager Wazuh | 514/udp | syslog RFC 5424 (audit de Keryx) | `keryx-sortie` | sortie ouverte, `KERYX_SYSLOG_HOST` |
| 19 | `keryx` | `www.virustotal.com` | 443/tcp | HTTPS | `keryx-sortie` | sortie ouverte **et** `KERYX_VIRUSTOTAL_ENABLED=true` |
| 20 | Administrateur | démon Docker de l'hôte | SSH de l'hôte | hors kit | : | administration |

Trois flux internes sont en clair (4, 10, 13) : chacun reste sur un réseau `internal` à deux conteneurs, sur la même machine. Pour le flux 13, Keryx chiffre chaque pièce avant l'envoi et signe chaque requête : ni le contenu ni le secret ne circulent (ADR-0019). Si ces services sont répartis sur plusieurs machines, ces flux doivent passer en TLS (PDIS IV.3.8.e).

**Limite à connaître** : un réseau Docker ouvert laisse sortir vers **n'importe quelle** destination. `KERYX_SORTIE_FERMEE=false` n'autorise pas « SMTP et l'horodatage » : il autorise tout. La liste blanche des lignes 15 à 19 se fait au pare-feu de l'hôte (chaîne `DOCKER-USER`) ou en amont. Constaté : sortie fermée, le conteneur `keryx` ne résout aucun nom externe et ne joint aucune adresse ; sortie ouverte, il joint tout.

**Après avoir changé un réglage de réseau** (`KERYX_SORTIE_FERMEE`, `KERYX_NET_PREFIX`) : `docker compose up -d` recrée le réseau. Si le sous-réseau du reverse proxy a changé, ajouter `--force-recreate` : un conteneur rebranché sur un réseau recréé perd son adresse fixe.

## 5. Les profils

### `antivirus`
ClamAV analyse chaque pièce déposée (flux 7). Constaté : une archive saine est marquée « sain », une archive contenant le fichier d'essai EICAR part en quarantaine et n'est resservie que dans l'archive chiffrée. **Dépendance hors UE** : les signatures viennent de `database.clamav.net` (Cisco, États-Unis). Rien n'est envoyé, mais le service apprend l'adresse de la machine et la fréquence des mises à jour. Pour s'en passer : `KERYX_CLAMAV_SORTIE_FERMEE=true` (ClamAV garde les signatures de l'image, qui vieillissent), ou un miroir privé dans la zone de mise à jour, en montant un `freshclam.conf` qui le désigne (`PrivateMirror`) ; ce second cas n'a pas été essayé.

### `sso`
Keycloak 26.8.2 et sa base. Deux realms importés au premier démarrage (`keycloak/realms/`), jamais réimportés ensuite :

- `soc` : managers et analystes ; `clients` : comptes des clients. Deux populations, deux realms (PDIS IV.3.9.d pour les opérateurs, IV.3.13.c pour le commanditaire).
- Client OpenID Connect `keryx` **confidentiel**, flux par code d'autorisation seulement, **PKCE S256 exigé**, une seule adresse de redirection (`https://<domaine>/api/v1/auth/oidc/<realm>/callback`), une seule adresse de retour après déconnexion (`/connexion`).
- **Second facteur exigé** : le flux de connexion `keryx-navigateur` rend le code OTP obligatoire après le mot de passe. Constaté : à sa première connexion, un utilisateur ne passe pas tant qu'il n'a pas enrôlé une application TOTP ; à la suivante, le code lui est demandé.
- Mot de passe : 12 caractères au moins ; protection contre la force brute ; inscription libre et réinitialisation par courriel désactivées ; HTTPS exigé.
- Rôles `manager`, `analyst` (realm `soc`) et `client` (realm `clients`) : **informatifs**. Keryx ne lit pas les rôles de Keycloak ; le rôle et les clients d'un compte restent ceux de Keryx (ADR-0017).

Côté Keryx, `install.sh` écrit `KERYX_OIDC_PROVIDERS` avec `"roles"` borné : `["manager","analyst"]` pour `soc`, `["client"]` pour `clients`. Constaté : un compte du realm `clients` portant l'identifiant et le courriel d'un analyste est refusé.

À faire à la main après l'installation : se connecter à la console (`https://<domaine de Keycloak>/admin/`) avec le compte d'amorçage de `.env`, créer un administrateur nominatif avec second facteur, supprimer le compte d'amorçage ; créer les utilisateurs avec **la même adresse courriel, vérifiée, que leur compte Keryx** (elle sert à la première liaison). La console et le realm `master` ne répondent qu'aux adresses de `KERYX_ADMIN_CIDRS` (par défaut les plages privées ; constaté : 403 depuis une autre adresse) : la resserrer sur les postes d'administration (PDIS IV.3.9.b).

Limites : `KERYX_OIDC_REQUIRED_ACR` n'est pas réglé (Keycloak n'annonce pas de niveau dédié sans configuration supplémentaire ; Keryx fait confiance au realm, ADR-0017). Keycloak n'envoie pas de courriel (pas de SMTP réglé). Une seule instance, sans haute disponibilité.

### `objets`
Garage 1.3.1, un nœud. `install.sh` lance le script du dépôt `deploy/garage/init.sh` (disposition, bucket `keryx-pieces`, clé dédiée), écrit les variables `KERYX_S3_*` dans `.env` et redémarre Keryx sur le stockage objet. Constaté : pièce déposée, relue identique, deux objets dans le bucket. **Un seul nœud n'est qu'un essai** (`docs/deploiement-stockage-garage.md` : trois nœuds sur trois sites en production). Des pièces déjà déposées sur disque ne sont pas déplacées : `docker compose exec keryx python -m keryx.cli migrate-attachments`.

*Reprendre l'initialisation de Garage* si elle a échoué en route (le script du dépôt n'est pas rejouable) : `./uninstall.sh`, supprimer les volumes `garage_meta` et `garage_data` s'ils ne contiennent rien d'utile (`docker volume rm`), relancer `./install.sh`.

### `sauvegarde`
Un conteneur de l'image de Keryx lance `keryx backup` au démarrage puis toutes les `KERYX_BACKUP_INTERVAL_S` secondes (un jour par défaut) et garde les `KERYX_BACKUP_KEEP` dernières archives (14). L'archive est chiffrée par Keryx (ADR-0015). Constaté : archive écrite, déchiffrée et vérifiée par `keryx restore` (empreintes du manifeste). **Écarts** : le volume est sur la même machine que les données (PDIS IV.3.6.c veut un dispositif de sauvegarde « dédié et hébergé dans une zone d'administration ») ; seules la base et les pièces sur disque sont couvertes, pas la configuration (`.env`, `certs/`), ni les volumes de Garage et de Keycloak ; la restauration dans une base vide n'a pas été rejouée ici (elle l'est par `tests/test_backup.py`). PDIS IV.3.6.b : tester le plan de restauration au moins une fois par an.

## 6. Ce déploiement et PDIS

*Référentiel « Prestataires de détection des incidents de sécurité », version 2.0 du 21/12/2017. Les exigences citées ont été lues dans le texte ; le reste du référentiel n'est pas couvert ici.*

**Le kit tout-en-un ne satisfait pas l'architecture qu'exige PDIS.** Il convient aux essais, aux démonstrations et à un petit SOC qui ne vise pas la qualification. Ce qu'il ne réalise pas :

| Exigence | Ce qu'elle demande | Ce que fait le kit |
|---|---|---|
| IV.3.8.b | Cloisonner le système d'information du service en zones de confiance : collecte, analyse, notification, échange commanditaire, administration, mise à jour, exploitation, échange | Tout est sur une machine. Les réseaux Docker séparent des conteneurs, pas des zones |
| IV.3.8.c | Cloisonnement entre zones « par des mécanismes de filtrage, d'authentification et de contrôle d'accès » | Filtrage entre conteneurs seulement |
| IV.3.10.b | Filtrer les flux aux interconnexions avec des solutions qualifiées par l'ANSSI | Aucun équipement de filtrage dans le kit |
| IV.3.10.c | Chiffrer les flux aux interconnexions par IPsec agréé (sauf mises à jour et notifications non sensibles) | HTTPS seul entre le manager Wazuh et Keryx |
| IV.3.13.b | « Une machine physique ou virtuelle par commanditaire » pour une instance du portail web et du stockage | Un seul Keryx sert tous les clients, portail compris |
| IV.3.13.g | Un pare-feu applicatif devant le portail web | Caddy borne et relaie ; ce n'est pas un pare-feu applicatif |
| IV.3.9.a, b | Administration depuis des postes dédiés, dans la zone d'administration, par des interfaces dédiées | L'administration du démon Docker passe par l'accès SSH de la machine, sans interface dédiée |
| IV.3.6.c | Dispositif de sauvegarde dédié, dans une zone d'administration | Volume sur la même machine |
| IV.3.11 | Mises à jour par dépôt relais dans une zone de mise à jour, filtrage par liste blanche | Les images viennent directement des registres publics |
| IV.3.12.a | Messagerie de notification dédiée, dans la zone de notification | Keryx parle au relais SMTP qu'on lui donne |

Ce que le kit apporte tout de même dans le sens du référentiel : le cloisonnement **logique** entre commanditaires que fait Keryx (IV.3.8.g : « au minimum logique »), un annuaire distinct pour les opérateurs et pour les commanditaires avec second facteur (IV.3.9.d, IV.3.13.c ; deux realms d'un même Keycloak, ce qu'un auditeur peut juger insuffisant pour « dédié »), des flux réduits et écrits (IV.3.8.d), l'hébergement dans l'UE s'il est choisi ainsi (IV.3.3).

### Architecture de référence, cible qualifiée

Les mêmes images, réparties par zone. Chaque trait vertical est un équipement de filtrage (IV.3.10.b) ; entre zones qui empruntent un réseau non dédié, chiffrement et authentification IP agréés (IV.3.8.e).

```
   Commanditaire                         Système d'information du service de détection
 ┌──────────────────┐   IPsec agréé   ┌───────────────────────────────────────────────────────────────┐
 │ Enclave de       │  (IV.3.10.c)    │ ZONE DE COLLECTE                 ZONE D'ANALYSE               │
 │ collecte         ├────────────────▶│  manager et indexeur Wazuh ────▶  caddy ─▶ keryx ─▶ postgres  │
 │ (agents, relais) │                 │                        (flux 2)   (console de l'équipe)       │
 └──────────────────┘                 │                                   clamav, garage (3 nœuds)    │
 ┌──────────────────┐   IPsec agréé   │ ZONE D'ÉCHANGE COMMANDITAIRE (IV.3.13)                        │
 │ Enclave de       ├────────────────▶│  pare-feu applicatif ─▶ caddy ─▶ PORTAIL CLIENT + stockage    │
 │ consultation     │                 │  une machine virtuelle PAR commanditaire (IV.3.13.b)          │
 │ (navigateurs)    │                 │  annuaire des commanditaires : keycloak, realm clients        │
 └──────────────────┘                 │ ZONE DE NOTIFICATION (IV.3.12) : relais SMTP dédié ──▶ courriel│
                                      │ ZONE D'EXPLOITATION : postes des opérateurs ─▶ console        │
                                      │ ZONE D'ADMINISTRATION (IV.3.9) : postes d'administration,     │
                                      │   annuaire des opérateurs (keycloak, realm soc), accès aux    │
                                      │   démons Docker, sauvegardes (IV.3.6.c), journaux, temps      │
                                      │ ZONE DE MISE À JOUR (IV.3.11) : registre d'images relais,     │
                                      │   miroir des signatures ClamAV, dépôt relais ──▶ Internet     │
                                      └───────────────────────────────────────────────────────────────┘
   ZONE INTERNET du prestataire, HORS du système d'information du service (IV.3.16) :
   postes dédiés, recherches en sources ouvertes (dont VirusTotal), journalisées (IV.3.16.f)
```

Ce qu'il faut pour y arriver, et que le kit ne fait pas :

1. **Portail client séparable de la console d'analyse : Keryx ne sait pas le faire.** Aujourd'hui un seul processus sert l'équipe et les clients, sur une seule base. IV.3.13.b veut une instance du portail et de son stockage par commanditaire, dans une autre zone que l'analyse. Déployer un Keryx complet par client y mettrait aussi la console des analystes et multiplierait leurs écrans : ce n'est pas la réponse. **Écart d'architecture à traiter dans Keryx** (un composant portail qui ne détient que les données d'un client, alimenté depuis la zone d'analyse) ; non conçu, non codé.
2. **Registre d'images interne et zone de mise à jour** (IV.3.11) : un registre relais qui seul télécharge, depuis une liste blanche de sources officielles (IV.3.11.c), avec contrôle d'authenticité et d'intégrité (IV.3.11.d : les images du kit sont épinglées par empreinte, c'est le point de départ). Les hôtes ne tirent que de ce registre ; `docker-compose.yml` ne change que par ses noms d'images. La construction de l'image de Keryx (paquets Debian, PyPI, npm) se fait dans cette zone, pas sur les hôtes. Les signatures ClamAV et le référentiel ATT&CK entrent par la même voie (IV.3.11.a, remarque sur les « référentiels »).
3. **Administration du démon Docker depuis la zone d'administration** (IV.3.9.a, b) : pas de socket Docker exposé sur le réseau ; accès par SSH depuis les postes d'administration, sur une interface dédiée ; journalisation des accès et des actions (IV.3.9.c) ; comptes d'administration dédiés (IV.3.9.e). La console de Keycloak ne répond qu'à cette zone (`KERYX_ADMIN_CIDRS`).
4. **Pare-feu applicatif** devant le portail (IV.3.13.g), filtrage qualifié aux interconnexions (IV.3.10.b), IPsec agréé (IV.3.10.c).
5. **Sauvegardes** dans la zone d'administration (IV.3.6.c), journaux exportés (ANSSI R16), serveur de temps de référence (IV.3.9.l).
6. **Un annuaire réellement dédié** aux commanditaires (IV.3.13.c) : une instance de Keycloak dans la zone d'échange commanditaire, distincte de celle des opérateurs.

### VirusTotal dans un déploiement visant la qualification : `KERYX_VIRUSTOTAL_ENABLED=false`

Le texte, lu au chapitre IV.3.7 (« Service de détection du service », c'est-à-dire la détection que le prestataire opère sur son propre système d'information) : IV.3.7.j recommande d'utiliser « des outils permettant de réaliser une analyse statique ou dynamique de fichiers suspects » ; IV.3.7.k ajoute : « Dans le cas où le prestataire utilise des outils d'analyse statiques ou dynamiques de fichiers suspects faisant appel à des ressources hébergées sur Internet, le prestataire doit réaliser ces opérations hors du système d'information du service de détection des incidents de sécurité ».

L'exigence est écrite pour ce chapitre, mais ce qu'elle interdit ne dépend pas de lui : un outil du système d'information du service qui interroge une ressource d'Internet à propos d'un fichier suspect. C'est ce que fait la recherche VirusTotal de Keryx. Le reste du référentiel va dans le même sens : la liste des interconnexions autorisées (IV.3.10.a) ne contient aucune sortie vers un service d'Internet, et les recherches en sources ouvertes se font depuis la zone internet, sur des postes dédiés, hors du système d'information du service, et sont journalisées (IV.3.16.a, d, f).

Donc, dans un déploiement qui vise la qualification : `KERYX_VIRUSTOTAL_ENABLED=false` et `KERYX_SORTIE_FERMEE=true` (ou un pare-feu qui n'ouvre pas `www.virustotal.com`). L'analyste fait la recherche depuis son poste de la zone internet. C'est la valeur du kit tant que la sortie de Keryx est fermée. Ailleurs, la décision de l'utilisateur consignée dans ADR-0022 (fonction disponible par défaut) s'applique dès que la sortie est ouverte. L'interprétation de IV.3.7.k appartient à l'organisme de qualification.

## 7. Dépendances hors de l'Union européenne

Règle du projet : aucune, sans décision écrite. Le socle (Keryx, PostgreSQL, Caddy en mode `fourni` ou `local`) n'en a **aucune à l'exécution**. Les autres, toutes signalées par `install.sh` au moment du choix :

| Dépendance | Quand | Ce qui sort | Pour s'en passer |
|---|---|---|---|
| Registres d'images (Docker Hub, quay.io) ; dépôts Debian, PyPI, npm | à la construction et à chaque mise à jour, pas à l'exécution | l'adresse de la machine, la liste de ce qui est téléchargé | registre et dépôts relais dans la zone de mise à jour (section 6) |
| Autorité ACME | mode `acme` | nom de domaine, adresse | choisir une autorité de l'UE, ou le mode `fourni` |
| `database.clamav.net` | profil `antivirus` | adresse, fréquence | miroir privé, ou fermer la sortie |
| `www.virustotal.com` | sortie ouverte et fonction active | une empreinte, la clé de l'analyste (ADR-0022) | `KERYX_VIRUSTOTAL_ENABLED=false` |

Les deux premières lignes existaient avant ce kit (le `Dockerfile` du dépôt tire déjà ses images et ses paquets des mêmes sources) ; elles sont écrites ici parce qu'un kit de déploiement les rend visibles.

## 8. Ce qui a été vérifié, et comment

Essai du 22/11/2026, mode `local`, ports 18080 et 18443, projet compose dédié, supprimé ensuite.

| Contrôle | Résultat |
|---|---|
| Construction des trois images (Keryx, Keycloak, Garage), constructeur classique | réussie ; contexte de Keryx : 305 ko |
| `install.sh` non interactif, socle | `.env` en mode 600, trois services sains, compte Admin créé |
| `/healthz` à travers Caddy, certificat vérifié contre l'autorité locale | 200, HTTP/2, TLS 1.3 ; TLS 1.0 et 1.1 refusés ; HTTP redirigé (308) vers le bon port |
| Activation du premier Admin avec le mot de passe temporaire et le code affichés | réussie (TOTP enrôlé, dix codes de secours) |
| `exemple-alerte.json` envoyée avec une clé d'API créée pour l'essai | 201, ticket `ACME-1` ; une fausse clé est refusée |
| Alerte envoyée par le vrai script `integrations/wazuh/custom-keryx.py`, certificat vérifié | 201, ticket `ACME-2` |
| Adresse du client vue par Keryx | celle du client, pas celle de Caddy (journal d'audit) |
| Dépôt d'une pièce de 19 Mio, racine en lecture seule, aucune capability | 201 ; 25 Mio et requête ordinaire de 3 Mio : 413 |
| Écoute sur le port 443 sans root ni capability (conteneur Caddy à part, l'essai lui-même utilisant 18443) | réussie |
| Huit conteneurs : `docker inspect` | lecture seule, `cap_drop ALL`, aucun `cap_add`, `no-new-privileges`, non root, limites mémoire, CPU et processus, journaux bornés |
| Profil `antivirus` | archive saine : « sain » ; EICAR : quarantaine ; signatures mises à jour |
| Profil `sso` | connexion complète par Keycloak (PKCE, OTP imposé puis demandé), liaison du compte, realm `clients` refusé pour un analyste, console d'administration filtrée par adresse |
| Profil `objets` | initialisation par `deploy/garage/init.sh`, pièce déposée et relue |
| Profil `sauvegarde` | archives écrites, l'une déchiffrée et vérifiée |
| Sortie de Keryx | fermée par défaut (rien ne sort), ouverte par `KERYX_SORTIE_FERMEE=false` |
| Relance d'`install.sh`, avec des variables contraires dans le terminal | `.env` identique (empreinte), mêmes conteneurs, pas de second Admin |
| `./uninstall.sh`, puis `docker compose up -d` | volumes conservés, données et realms retrouvés |
| `docker compose config` : 3 modes × 16 combinaisons de profils | 48 réussites, aucun avertissement |
| `caddy validate` : `local`, `acme`, `acme` avec liaison de compte, avec et sans site Keycloak | configuration valide |
| `sh -n` et `shellcheck` sur `install.sh`, `uninstall.sh`, `sauvegarde.sh` | aucune remarque |
| `install.sh` avec un faux `docker` : modes `acme` et `fourni`, questions tapées dans un pseudo-terminal, refus (autorité absente, domaine invalide, profil inconnu, certificat manquant) | conformes |

**Constat fait pendant l'essai, non corrigé dans Keryx** : quand une requête dépasse sa borne, Keryx répond 413 puis coupe la connexion sans lire le corps (`keryx/bodylimit.py`). Un reverse proxy encore en train d'envoyer ce corps peut voir la connexion rompue avant d'avoir lu la réponse, et répond alors 502 : constaté sur une pièce de 25 Mio (« connection reset by peer » dans le journal de Caddy). Le kit le contourne en appliquant les mêmes bornes dans Caddy, qui répond lui-même 413 avec le même message (constaté ensuite : 413). Le cas qui reste passe par Keryx seul : une requête sans session, entre 2 et 21 Mio, vers la route de dépôt ; essayée une fois à 10 Mio, elle a bien reçu 413, mais rien ne garantit que ce soit toujours le cas. À traiter dans Keryx.
