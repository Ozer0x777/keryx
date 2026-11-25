# Architecture

*In English: Keryx is a single FastAPI application that also serves its React interface, backed by PostgreSQL (SQLite
for tests). Wazuh pushes alerts over HTTPS; every other external service is optional and off by default.*

Vue d'ensemble. Les choix et leurs raisons sont dans les ADR (`docs/adr/`), le schéma de la base dans
`docs/modele-donnees.md`, le lien exigence, code et test dans `docs/matrice-tracabilite.md`.

## Composants

```
                         HTTPS (TLS 1.2+)
  Navigateurs  ───────────────────────────►  Caddy (proxy TLS)  ──►  Keryx (FastAPI + interface React)
  (équipe, clients)                                                    │      │
                                                                       │      ├─► PostgreSQL 16 (base)
  Manager Wazuh ── intégration keryx (HTTPS, clé d'API par client) ───►│      ├─► disque ou stockage objet S3 (pièces)
                                                                       │      │
                                         sorties facultatives, désactivées par défaut :
                                         SMTP, ClamAV, Keycloak (OIDC), autorité d'horodatage RFC 3161,
                                         syslog RFC 5424, indexeur et API du manager Wazuh d'un client (lecture
                                         seule), VirusTotal (recherche d'empreinte)
```

| Composant | Rôle | Code |
|---|---|---|
| API | Routes REST `/api/v1/*`, sessions, contrôle d'accès, description OpenAPI sur `/api/openapi.json` | `keryx/api.py`, `keryx/routes_*.py` |
| Interface | Application React construite par Vite, servie par l'API, sans ressource externe (CSP stricte) | `web/src/` |
| Ingestion | Alerte Wazuh vers ticket pré-rempli, ou rattachement à un ticket ouvert (déduplication) | `keryx/ingest.py`, `integrations/wazuh/` |
| Modèle et base | SQLAlchemy 2, migrations Alembic versionnées | `keryx/models.py`, `keryx/db.py`, `migrations/` |
| Sécurité | Argon2id, TOTP, WebAuthn, OIDC, clés d'API, chiffrement des secrets au repos (AES-256-GCM) | `keryx/security.py`, `keryx/oidc.py`, `keryx/routes_webauthn.py` |
| Audit | Journal chaîné et scellé (HMAC-SHA256), points de contrôle, export syslog | `keryx/audit.py` |
| Preuves | Pièces jointes, empreintes SHA-256, chaîne de possession, quarantaine, horodatage | `keryx/attachments.py`, `keryx/s3store.py`, `keryx/timestamping.py` |
| Référentiels | Cycle de vie ISO/IEC 27035, MITRE ATT&CK, ETSI ISI, IODEF | `keryx/workflow.py`, `keryx/mitre*.py`, `keryx/isi.py`, `keryx/iodef.py` |
| Connecteurs Wazuh | Contexte d'un ticket dans l'indexeur, parc d'agents dans l'API du manager, en lecture seule | `keryx/wazuh_context.py`, `keryx/wazuh_agents.py` |
| Tâches de fond | Deux fils dans le processus : relance des notifications, relevé du parc d'agents | `keryx/api.py` (`notify-retry`, `parc-wazuh`) |
| Administration | Ligne de commande tracée au journal d'audit : comptes, clients, clés, sauvegarde | `keryx/cli.py`, `keryx/backup.py` |

## Acteurs et actions

Les droits sont vérifiés par le serveur, route par route (`require_role` dans `keryx/api.py` et `keryx/routes_*.py`),
et le cloisonnement par client dans la couche d'accès aux données. Le détail du quotidien de chaque rôle est dans
`docs/prise-en-main/`.

| Acteur | Comment il agit | Ce qu'il peut faire | Ce qu'il ne peut pas faire |
|---|---|---|---|
| Analyste | Interface web (mot de passe et second facteur, ou SSO OIDC) | Sur les tickets de ses clients : qualifier (gravité, verdict, MITRE ATT&CK, ETSI ISI), changer le statut, affecter, rédiger le corps et la synthèse, commenter (interne ou visible du client), lier et fusionner des tickets, déposer et suivre les pièces (chaîne de possession, restitution, horodatage), exporter en IODEF ; consulter le contexte Wazuh, chercher une empreinte sur VirusTotal et relever le parc d'agents quand ces connecteurs sont activés ; ouvrir le mode crise et tenir son registre | Lire les tickets d'un client qui ne lui est pas rattaché ; détruire une pièce ; clore le mode crise ; administrer les comptes |
| Manager | Interface web | Tout ce que fait l'analyste, plus : détruire une pièce, clore le mode crise, tenir la table MITRE et ses imports, consulter et exporter le journal d'audit, piloter l'équipe (tableau de bord, rapports périodiques, registre, affectation en masse, modèles communs) | Administrer les comptes, clients et clés d'API |
| Client | Portail web, cloisonné à son client | Suivre ses incidents (statut, gravité, éléments marqués visibles), répondre au SOC, déposer un fichier, consulter son parc d'agents | Voir les commentaires internes, les motifs de faux positif, les recherches VirusTotal, le contexte Wazuh, les données d'un autre client |
| Admin | Interface web et ligne de commande | Comptes (création, rôle, rattachement aux clients, réinitialisation du mot de passe et du second facteur, revue des comptes), clients, clés d'API Wazuh, accès d'un client à son indexeur et à son API Wazuh, table MITRE, rétention, état du système, journal d'audit (vérification, points de contrôle) | Lire le contenu des tickets, le parc d'agents des clients ou le détail des actions sur les tickets dans le journal |
| Intégration Wazuh d'un client | Requête HTTPS avec la clé d'API de ce client | Envoyer une alerte : ouverture d'un ticket pré-rempli ou rattachement à un ticket ouvert | Toute autre route ; écrire pour un autre client que celui de sa clé |
| Opérateur du serveur | Ligne de commande `keryx` sur l'hôte, chaque action tracée au journal | Créer le premier compte, les clients et les clés, sauvegarder et restaurer, vérifier la chaîne d'audit, charger un jeu de démonstration | (accès à l'hôte : hors du contrôle de l'application, voir `docs/securite.md`) |
| Services externes | Appelés par Keryx seulement, jamais l'inverse (sauf le retour OIDC) | Messagerie, antivirus, fournisseur d'identité, autorité d'horodatage, syslog, indexeur et API du manager Wazuh d'un client (lecture seule), VirusTotal | Recevoir autre chose que ce que leur fonction exige (VirusTotal ne reçoit qu'une empreinte, jamais un fichier) |

## Flux principal

1. Wazuh déclenche l'intégration pour une alerte au-dessus du seuil ; le script envoie l'alerte en HTTPS avec la clé
   d'API du client.
2. Keryx identifie le client par la clé, ouvre un ticket pré-rempli (règle, équipement, criticité initiale, MITRE)
   ou incrémente les occurrences d'un ticket ouvert pour la même règle et le même équipement.
3. L'équipe qualifie (gravité, verdict), traite, documente (preuves, commentaires), clôt ; chaque action est écrite
   au journal d'audit.
4. Le client suit ses tickets sur son portail, cloisonné : il ne voit que les données de son client marquées
   visibles.

## Frontières de confiance

| Frontière | Ce qui la traverse | Contrôle |
|---|---|---|
| Internet ou réseau client vers Caddy | Navigateurs, alertes Wazuh | TLS 1.2 minimum, 1.3 préféré |
| Caddy vers Keryx | Requêtes HTTP | Adresse du proxy seule de confiance (`FORWARDED_ALLOW_IPS`), taille des corps bornée avant l'application |
| Utilisateur vers données | Lecture et écriture des tickets | Session, double authentification, rôle, cloisonnement par client dans la couche d'accès |
| Keryx vers services externes | Requêtes sortantes | TLS vérifié par défaut, aucune redirection suivie, délais bornés, secrets chiffrés au repos |
| Contenu fourni (alertes, pièces, HTML) | Données non fiables | HTML assaini côté serveur, images ré-encodées, archives jamais décompressées, antivirus, échappement à l'affichage |

L'argumentaire de sécurité complet est dans `docs/securite.md`.

## Déploiement

Kit Docker (`deploy/docker/`, ADR-0023) : Caddy, Keryx et PostgreSQL au minimum ; profils facultatifs ClamAV,
Keycloak (avec sa base), Garage (stockage objet) et sauvegarde planifiée. Conteneurs sans capability, en lecture
seule, sans root. Image publiée et signée à chaque version (`docs/publication.md`).

Limite : un seul processus Keryx. Les limites de débit sont partagées en base sous PostgreSQL (en mémoire sous
SQLite, ADR-0010), mais les deux fils de fond tournent dans chaque processus ; plusieurs instances et la haute
disponibilité n'ont pas été conçues ni testées.
