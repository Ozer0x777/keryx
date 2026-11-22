# ADR-0023 — Déploiement par conteneurs

- **Statut** : accepté (22/11/2026). **Essayé pour de bon** en mode `local` avec tous les profils (Docker 29.9.3, compose 5.7.0) : voir `docs/deploiement-docker.md`, section 8. **Pas essayé** : le mode `acme`, le mode `fourni` avec un vrai certificat, un vrai manager Wazuh, les réglages du démon Docker (`userns-remap`, `bridge: none`, pilote de journaux).
- **Pourquoi** : installer Keryx demandait jusqu'ici d'assembler à la main la base, le proxy TLS, l'antivirus, l'annuaire et le stockage objet, chacun décrit dans un guide différent. Un essai prenait une journée et chaque installation était différente, donc impossible à durcir une fois pour toutes.
- **Exigences** : fiche ANSSI-FT-082 « Recommandations de sécurité relatives aux déploiements de conteneur Docker » (23/09/2020), R1 à R16, lue en entier ; PDIS v2.0, IV.3.8.d (matrice des flux), IV.3.6 (sauvegardes), IV.3.9.d et IV.3.13.c (annuaires, second facteur), IV.3.3 (Union européenne) ; RFC 9325 (TLS 1.2 au minimum) et RFC 6797 (HSTS), déjà retenues par le projet. Le kit **ne** satisfait **pas** IV.3.8.b, IV.3.10.b et c, IV.3.13.b et g, IV.3.6.c, IV.3.11 : c'est écrit dans la référence, section 6.
- **Dépendance** : aucune bibliothèque ajoutée à Keryx. Images tierces, toutes libres et épinglées par empreinte : PostgreSQL 16.16, Caddy 2.11.9, ClamAV 1.4.7, Keycloak 26.8.2, Garage 1.3.1.

## Décisions de l'utilisateur (22/11/2026)

Un conteneur par service. **Un seul** fichier compose, avec des **profils**. HTTPS dans les deux modes : certificat automatique (ACME) ou certificat fourni. Keycloak et Garage en profils facultatifs qui arrivent configurés.

## Choix techniques

1. **Reverse proxy : Caddy.** Il sait obtenir un certificat par ACME, en charger un fourni ou en signer un pour un essai, avec la même configuration, et son réglage par défaut refuse déjà TLS 1.0 et 1.1. *Écarté* : nginx avec certbot (deux conteneurs et un volume partagé pour le seul certificat) ; Traefik (dans son usage habituel avec Docker, il lit le socket Docker pour découvrir les services, ce que l'annexe de la fiche rattache à R1).
2. **Trois modes choisis par une variable** (`KERYX_HTTPS_MODE`), un fichier de quelques lignes par mode dans `caddy/tls/`. *Écarté* : un fichier compose par mode (décision : un seul fichier).
3. **Le mode ACME n'a pas d'autorité par défaut.** Sans réglage, Caddy s'adresse à Let's Encrypt, exploité aux États-Unis. La règle du projet interdit une dépendance hors de l'Union européenne sans décision écrite : `install.sh` exige l'adresse de l'annuaire ACME de l'autorité choisie. Aucune autorité de l'UE n'est proposée, faute d'en avoir vérifié une. **À trancher par l'utilisateur** s'il veut un défaut.
4. **Durcissement identique pour tous les services** (bloc `x-durci`) : aucune capability, `no-new-privileges`, racine en lecture seule, utilisateur sans privilège, limites de mémoire, de CPU et de processus, journaux bornés. Pour y arriver sans exception : PostgreSQL et ClamAV démarrent directement sous leur utilisateur ; Keycloak et Garage ont chacun une image dérivée minimale (construction préalable pour l'un, propriétaire des dossiers de données pour l'autre) ; le `Dockerfile` de Keryx crée `/sauvegardes`. *Écarté* : un conteneur d'initialisation qui ferait `chown` sur les volumes (il lui faudrait `CAP_CHOWN`, que la fiche range parmi les capabilities sensibles).
5. **Un réseau par connexion** (R5), `internal` sauf deux : l'entrée, et la sortie de ClamAV vers ses signatures. **La sortie de Keryx est fermée par défaut** (`KERYX_SORTIE_FERMEE`). Conséquence assumée : sans action, pas de courriel, pas d'horodatage, pas de contexte Wazuh, pas de VirusTotal ; `install.sh` pose la question.
6. **Caddy écoute sur les ports publics eux-mêmes** (80 et 443 dans le conteneur), sans capability : Docker ouvre les ports bas dans l'espace réseau d'un conteneur. La fiche conseille plutôt un port haut redirigé ; ce n'est pas retenu parce que Keryx doit joindre Keycloak par son adresse publique en passant par Caddy, sur le même port que les navigateurs. L'objectif de la fiche (pas de `CAP_NET_BIND_SERVICE`) est tenu.
7. **Secrets dans `.env`, transmis par l'environnement**, pas par les secrets de compose. Keryx ne lit ses secrets que dans son environnement ; compose refuse un secret tiré d'une variable sur un conteneur en lecture seule, et un secret tiré d'un fichier n'est pas lisible par un conteneur sans root ni capability. Entre les deux, le durcissement l'emporte. *Limite* : `docker inspect` montre les secrets à qui a accès au démon.
8. **`install.sh` n'écrit jamais dans un `.env` existant, sauf pour y ajouter une variable absente.** Il retire de son environnement toutes les variables que compose lit, parce qu'une variable du terminal l'emporterait sur `.env` et reconfigurerait un déploiement en place (constaté pendant l'essai, puis corrigé).
9. **Premier compte Admin par code d'activation.** `keryx add-user` affichait le secret TOTP et les codes de secours dans le terminal et laissait le mot de passe inchangé. Ajout de `--activation` : même parcours qu'un compte créé dans l'interface (mot de passe temporaire, code d'activation à usage unique valable 72 h, TOTP enrôlé par le titulaire). C'est la **seule modification du code de Keryx**, couverte par `tests/test_enrollment.py`.
10. **VirusTotal coupé tant que la sortie est fermée** (`KERYX_VIRUSTOTAL_ENABLED=false` dans le `.env` écrit par `install.sh`), actif si l'utilisateur ouvre la sortie : la décision d'ADR-0022 n'est pas remise en cause, le kit évite seulement un bouton qui ne peut pas aboutir. Dans un déploiement visant la qualification : `false` (PDIS IV.3.7.k, ADR-0022).
11. **Bornes de taille des requêtes reprises dans Caddy**, par route, identiques à celles de Keryx : sinon un dépôt trop gros revient en 502 (référence, section 8).

## Alternatives d'ensemble écartées

- **Kubernetes** (ou un graphique Helm) : hors de proportion pour une machine ; la cible qualifiée de la référence répartit les mêmes images par zone sans l'imposer.
- **Paquets système et unités systemd** : pas d'isolation uniforme entre services, et autant de variantes que de distributions.
- **Tout dans un conteneur** : contraire à la décision, et à R5.
- **Podman** : non essayé. Rien dans le kit n'en dépend ni ne l'exclut ; la fiche de l'ANSSI porte sur Docker.

## Limites

- **Ce n'est pas une architecture PDIS** : une machine, pas de zones (IV.3.8.b), pas une machine par commanditaire pour le portail (IV.3.13.b), pas de pare-feu applicatif (IV.3.13.g). Keryx ne sait pas séparer son portail client de sa console d'analyse : écart d'architecture ouvert, non traité ici.
- **Réglages de l'hôte non faits** : `userns-remap` (R7), `bridge: none` (R3), export des journaux (R16), taille maximale des volumes (R14).
- **Dépendances hors UE** : registres d'images et dépôts de paquets à la construction ; signatures ClamAV ; autorité ACME selon le choix ; VirusTotal si activé (référence, section 7).
- **Ouvrir la sortie de Keryx l'ouvre vers tout** : le filtrage par destination est à faire au pare-feu de l'hôte.
- Images de base du `Dockerfile` de Keryx non épinglées par empreinte. Keycloak et Garage en instance unique. Sauvegardes sur la même machine. Garage : `deploy/garage/init.sh` n'est pas rejouable.
- Keryx coupe la connexion après un 413 : contourné dans Caddy, à corriger dans Keryx.
