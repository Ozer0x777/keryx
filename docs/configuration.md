# Configuration

Toutes les variables d'environnement lues par Keryx. Le kit Docker (`deploy/docker/`) en règle la plupart lui-même.

| Variable | Rôle | Défaut |
|---|---|---|
| `KERYX_DATABASE_URL` | SQLite (tests) ou PostgreSQL, ex. `postgresql+psycopg://u:p@hôte/base` (production) | `sqlite:///./keryx.db` |
| `KERYX_MAX_BODY_BYTES` | Taille maximale d'une requête ordinaire, contrôlée avant lecture, voir `docs/exploitation.md` | `2097152` |
| `KERYX_OIDC_PROVIDERS`, `KERYX_OIDC_ENFORCE`, `KERYX_OIDC_REQUIRED_ACR`, `KERYX_OIDC_ALLOW_HTTP` | SSO OpenID Connect (Keycloak), voir `docs/exploitation.md` et ADR-0017 | désactivé |
| `KERYX_STORAGE`, `KERYX_S3_*`, `KERYX_QUARANTINE_PASSWORD` | Stockage objet S3 chiffré avant envoi ; mot de passe de l'archive de quarantaine, voir ADR-0019 | disque ; « infected » |
| `KERYX_TSA_URL`, `KERYX_TSA_CA_FILE`, `KERYX_TSA_USER`/`_PASSWORD`/`_BEARER`/`_CLIENT_CERT`/`_CLIENT_KEY`, `KERYX_TSA_POLICY_OID` | Horodatage de confiance RFC 3161 (autorité à choisir dans l'UE), voir ADR-0018 | désactivé |
| `KERYX_WAZUH_ALLOW_LOOPBACK`, `KERYX_WAZUH_TIME_FIELD`, `KERYX_WAZUH_CONTEXT_USER_LIMIT`, `KERYX_WAZUH_CONTEXT_CLIENT_LIMIT` | Contexte Wazuh (lecture de l'indexeur) : le reste se règle par client dans l'administration, voir ADR-0021 | boucle locale refusée ; `timestamp` ; 20 et 60 par minute |
| `KERYX_VIRUSTOTAL_ENABLED` | Recherche d'une empreinte de fichier sur VirusTotal (**service externe hors UE**, dérogation ADR-0022) : seule l'empreinte sort, avec la clé d'API que chaque analyste saisit dans son profil. `false` coupe la fonction pour toute l'instance | `true` |
| `KERYX_VIRUSTOTAL_USER_LIMIT`, `KERYX_VIRUSTOTAL_CLIENT_LIMIT`, `KERYX_VIRUSTOTAL_PROXY` | Recherches VirusTotal par minute, par utilisateur et par client ; mandataire HTTP explicite de cette sortie (les variables `HTTP_PROXY` ne sont pas lues) | 4 et 20 ; aucun |
| `KERYX_VIRUSTOTAL_URL`, `KERYX_VIRUSTOTAL_ALLOW_LOOPBACK` | **Essais seulement** : adresse d'un faux VirusTotal (HTTPS, ou HTTP sur la boucle locale avec la dérogation). Ne pas régler en production | `https://www.virustotal.com` ; refusée |
| `KERYX_LOGIN_USER_LIMIT` | Tentatives de connexion par identifiant et par 5 minutes | 10 |
| `KERYX_LOGIN_IP_LIMIT` | Tentatives de connexion par adresse IP et par 5 minutes | 30 |
| `KERYX_RATE_LIMIT_BACKEND` | `memory` (par processus) ou `db` (partagée entre processus) | `db` si PostgreSQL |
| `KERYX_RETENTION_MONTHS` | Rétention des alertes brutes des tickets clos (6 minimum) | 12 |
| `KERYX_NOTIFY_RETRY_S` | Intervalle de relance des courriels en échec (0 = désactivée) | 300 |
| `KERYX_SECRET_KEY` | Clé maîtresse 32 octets base64 (`keryx gen-key`) : obligatoire | aucun |
| `KERYX_PUBLIC_URL` | URL utilisée dans les liens des notifications | `https://keryx.local` |
| `KERYX_SMTP_HOST`, `_PORT`, `_TLS` (`starttls`/`ssl`), `_USER`, `_PASSWORD`, `_FROM` | Envoi des notifications | désactivé |
| `KERYX_ATTACHMENTS_DIR` | Stockage des pièces (hors racine web) | `./data/attachments` |
| `KERYX_CLAMAV_HOST`, `_PORT` | Analyse antivirus clamd | désactivé |
| `KERYX_SYSLOG_HOST`, `_PORT` | Copie du journal d'audit en syslog RFC 5424 (vers Wazuh) | désactivé |
| `KERYX_MIN_RULE_LEVEL`, `KERYX_DEDUP_MINUTES` | Seuil d'ouverture de ticket, fenêtre de dédoublonnage | 7, 15 |
