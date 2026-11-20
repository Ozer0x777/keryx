# Keryx — v0.2

Outil open source de gestion d'incidents de sécurité alimenté par Wazuh. Une alerte Wazuh arrive,
Keryx ouvre un ticket pré-rempli (description, criticité, règle, équipement, MITRE ATT&CK),
le registre, notifie le client par la seule référence, et trace tout dans un journal d'audit scellé.


## Démarrer en local (SQLite)

```bash
pip install -r requirements-dev.txt
(cd web && npm ci && npm run build)          # interface servie par FastAPI depuis keryx/web_dist

export KERYX_DATABASE_URL=sqlite:///./keryx.db
export KERYX_SECRET_KEY=$(python -m keryx.cli gen-key)   # à conserver : chiffre les secrets TOTP et scelle l'audit
export KERYX_COOKIE_SECURE=false            # uniquement en local sans HTTPS
alembic upgrade head                        # crée / met à jour le schéma

python -m keryx.cli add-client ACME "ACME Industrie"
python -m keryx.cli set-contacts ACME soc@acme.example
python -m keryx.cli add-user sbenali "S. Benali" analyst --clients ACME   # affiche l'URI TOTP et 10 codes de secours
python -m keryx.cli add-api-key ACME wazuh-manager-01
python -m keryx.cli add-mitre --group authentication_failures T1110 "Brute Force" "Credential Access"
uvicorn keryx.api:create_app --factory --port 8000
```

Interface : http://localhost:8000 (connexion mot de passe + TOTP). En développement de l'interface :
`cd web && npm run dev` (port 5173, l'API est relayée vers le port 8000).

Envoyer une alerte de test :

```bash
curl -X POST http://localhost:8000/api/v1/ingest/wazuh \
  -H "Authorization: Bearer kx_..." -H "Content-Type: application/json" \
  -d @exemple-alerte.json
```

Brancher un vrai Wazuh : voir `integrations/wazuh/README.md` (script d'intégration avec file d'attente locale si Keryx est injoignable).

## Conteneur

```bash
docker build -t keryx:0.2 .
docker run -p 8000:8000 -v keryx-data:/data \
  -e KERYX_SECRET_KEY=... -e KERYX_DATABASE_URL=sqlite:////data/keryx.db keryx:0.2
```

Le conteneur applique `alembic upgrade head` puis démarre. Dépendances installées depuis `requirements.lock`
(versions et empreintes figées, `--require-hashes`). Toujours placer Keryx derrière un proxy TLS.

## Configuration (variables d'environnement)

| Variable | Rôle | Défaut |
|---|---|---|
| `KERYX_DATABASE_URL` | SQLite (tests) ou PostgreSQL (production) | `sqlite:///./keryx.db` |
| `KERYX_SECRET_KEY` | Clé maîtresse 32 octets base64 (`keryx gen-key`) — obligatoire | — |
| `KERYX_PUBLIC_URL` | URL utilisée dans les liens des notifications | `https://keryx.local` |
| `KERYX_SMTP_HOST`, `_PORT`, `_TLS` (`starttls`/`ssl`), `_USER`, `_PASSWORD`, `_FROM` | Envoi des notifications | désactivé |
| `KERYX_ATTACHMENTS_DIR` | Stockage des pièces (hors racine web) | `./data/attachments` |
| `KERYX_CLAMAV_HOST`, `_PORT` | Analyse antivirus clamd | désactivé |
| `KERYX_SYSLOG_HOST`, `_PORT` | Copie du journal d'audit en syslog RFC 5424 (vers Wazuh) | désactivé |
| `KERYX_MIN_RULE_LEVEL`, `KERYX_DEDUP_MINUTES` | Seuil d'ouverture de ticket, fenêtre de dédoublonnage | 7, 15 |

## Tests

```bash
python -m pytest -q
```

88 tests avec des alertes Wazuh simulées : ingestion, cloisonnement par client, workflow, audit,
régressions de la revue de sécurité, migrations, notifications (SMTP simulé), pièces jointes (clamd simulé, EICAR).

## Ce que fait Keryx

| Fonction | Exigences |
|---|---|
| Ingestion `POST /api/v1/ingest/wazuh`, clé d'API par manager et par client, idempotence et dédoublonnage 15 min | PDIS IV.3.8.g, IV.3.10.e, IV.2.1.w |
| Ticket pré-rempli (règles, équipements, identifiants, criticité, MITRE), alerte brute + SHA-256 | PDIS IV.2.1.w, aa ; IV.2.2.s |
| Criticité initiale (niveau Wazuh) / gravité qualifiée (grille par client) | PDIS IV.2.1.e, q, r, s |
| MITRE en cascade Wazuh → table → correction manuelle tracée | Décision projet, ISO 27035 |
| Cycle ISO 27035, qualification obligatoire, synthèse et REX obligatoire si Élevée/Critique | ISO/IEC 27035-1, PRIS VI.5.3.e, ISO 27002 5.27 |
| Interface web : liste, Kanban, ticket, portail client, administration | Maquettes validées |
| Rôles Admin/Manager/Analyste/Client, cloisonnement par client, admin sans accès au contenu | PDIS IV.3.8.g, IV.3.9.d–h, PRIS IV.3.d |
| Argon2id + TOTP obligatoire (secret chiffré) + codes de secours + anti-rejeu + limites de débit | RFC 9106, 6238, 6585 ; ADR-0006, 0010 |
| Session cookie HttpOnly/Secure/SameSite, rotation, CSRF, inactivité 30 min | RFC 6265, ASVS chap. 7 |
| HTML assaini (nh3, liste blanche) ; CSP sans source externe | ASVS chap. 1, 3 |
| Pièces jointes 20 Mo, images ré-encodées, registre de collecte, ClamAV + quarantaine, chaîne de possession, preuves externes | PRIS VI.5.3.c, VI.2.4 ; ISO/IEC 27037 ; RFC 3227 ; ADR-0008 |
| Notifications SMTP (référence + lien seulement) avec registre | PDIS IV.2.3.g, h, j ; ADR-0009 |
| Journal d'audit scellé HMAC, point de contrôle externe, export syslog | PDIS IV.3.9.c, ISO 27002 8.15, RFC 5424 ; ADR-0007 |
| Revue des comptes et des droits | PDIS IV.3.4.b |
| Export IODEF JSON (sous-ensemble) | RFC 7970, RFC 8727 |
| Erreurs Problem Details, UUIDv7, dates RFC 3339 UTC, no-store, HSTS | RFC 9457, 9562, 3339, 9111, 6797 |
| Migrations Alembic | ISO 27002 8.32 ; ADR-0005 |

## Limites connues

- Limites de débit en mémoire, par processus : un seul processus uvicorn tant qu'elles ne sont pas partagées (ADR-0010).
- Quarantaine : fichier isolé et marqué, pas rezippé avec mot de passe (ADR-0008).
- Chemins PostgreSQL (verrou consultatif, migrations) non testés ; tests sous SQLite seulement.
- Jamais testé contre un vrai manager Wazuh.
- Interface testée dans Chrome sans tête (parcours analyste, client, admin) ; pas d'audit d'accessibilité RGAA complet.
- Pas encore : gestion des comptes depuis l'interface, Keycloak, import STIX d'ATT&CK, IODEF validé contre le schéma, format ETSI ISI, horodatage RFC 3161, nouvelle tentative d'envoi des courriels.

Un outil ne qualifie pas un prestataire : Keryx fournit les registres, la traçabilité et le
cloisonnement exigés par PDIS/PRIS, la qualification reste organisationnelle.
