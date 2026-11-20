# Matrice de traçabilité (exigence → fonction → code → test)

Les références d'exigence sont reprises du plan de projet. Les normes ISO et ETSI étant payantes, leur texte exact n'a pas été consulté : les renvois qui les concernent sont à confronter à la norme avant toute homologation.

| Exigence | Fonction | Code | Test |
|---|---|---|---|
| PDIS IV.2.1.w | Ticket pré-rempli depuis l'alerte Wazuh | `ingest.py` | `test_ingest.py` |
| PDIS IV.2.1.aa, IV.2.2.s | Alerte brute conservée avec empreinte | `ingest.py`, `models.RawAlert` | `test_ingest.py` |
| PDIS IV.2.1.q | Qualification obligatoire avant réponse | `workflow.py`, `api.qualify` | `test_workflow_audit.py` |
| PDIS IV.2.1.e, r, s | Grille de gravité par client ; délais cibles (SLA) par client | `severity.py`, `sla.py`, `routes_admin.clients_patch` | `test_workflow_audit.py`, `test_admin.py`, `test_work.py` |
| PDIS IV.2.1.bb | Registre chronologique par client, export CSV | `routes_reports.registry` | `test_reports.py` |
| PDIS IV.2.1.y | Export IODEF (contrôle structurel). Format ETSI ISI : **non fait**, spécification à consulter | `api.export_iodef`, `iodef.py` | `test_reports.py` |
| PDIS IV.2.2.w | Rétention paramétrable, purge tracée | `retention.py`, `routes_ops.retention_run` | `test_ops.py` |
| PDIS IV.2.3.g, h, j | Notification par référence seule, registre, relance des échecs | `notify.py` | `test_notifications.py` |
| PDIS IV.2.3.l | Portail client (rôle Client) | `api.py`, `Tickets.jsx`, `Ticket.jsx` | `test_access.py`, `20-travail.mjs` |
| PDIS IV.3.4.b ; PRIS IV.3.n, o | Revue des comptes et des droits | `api.account_review`, `admin/Review.jsx` | `test_admin.py` |
| PDIS IV.3.6 | Sauvegardes chiffrées et restauration vérifiée | `backup.py`, `cli.py` | `test_backup.py` |
| PDIS IV.3.8.g | Cloisonnement par client dans la couche d'accès | `api.load_ticket`, `visible_tenant_ids` | `test_access.py`, `test_work.py`, `test_reports.py`, `test_ops.py` |
| PDIS IV.3.9.c | Journal d'audit chaîné, consultable, point de contrôle | `audit.py`, `routes_ops.py` | `test_workflow_audit.py`, `test_ops.py` |
| PDIS IV.3.9.d à h | Séparation Admin / opérateurs (aucun accès au contenu des tickets, détails d'audit masqués) | `api.visible_tenant_ids`, `routes_ops.audit_entries` | `test_access.py`, `test_ops.py`, `10-admin.mjs`, `40-conformite.mjs` |
| PRIS VI.5.3.c | Registre des informations collectées (pièces) | `attachments.py`, `api.upload_attachment` | `test_attachments.py` |
| PRIS VI.5.3.d | Registre des actions du ticket | `api.event`, `models.TicketEvent` | `test_workflow_audit.py` |
| PRIS VI.5.3.e | Synthèse évolutive et REX obligatoire (Élevée/Critique) | `api.set_synthese`, `workflow.py` | `test_workflow_audit.py`, `test_fixes_revue2.py` |
| PRIS VI.5.5.1 | Registre de crise | `routes_ops.py`, `Crisis.jsx` | `test_ops.py`, `40-conformite.mjs` |
| PRIS VI.2.4 | Conservation, restitution, destruction des pièces | `api.lifecycle` | `test_attachments.py`, `test_fixes_revue2.py` |
| PRIS IV.3.q | Quarantaine des codes malveillants | `attachments.py` | `test_attachments.py` |
| ISO/IEC 27035-1 | Cycle de vie des incidents, liens et fusion, mesure des délais | `workflow.py`, `routes_work.py`, `routes_reports.py` | `test_workflow_audit.py`, `test_work.py`, `test_reports.py` |
| RFC 6238, 9106 | TOTP, Argon2id | `security.py` | `test_access.py`, `test_unit.py` |
| RFC 6265, ASVS V7 | Sessions : cookie HttpOnly, CSRF, rotation, inactivité | `api.py` | `test_access.py` |
| RFC 7970, 8727 | Export IODEF JSON (sous-ensemble contrôlé) | `iodef.py` | `test_reports.py` |
| RFC 3161 | Horodatage de confiance : **non fait** (autorité d'horodatage UE à choisir, dépendance ASN.1 à ajouter) | — | — |
| WCAG 2.1 A/AA (base du RGAA) | Contrôle automatisé axe-core sur 19 écrans de 3 rôles. Ne remplace pas un audit RGAA complet | `e2e/scenarios/90-accessibilite.mjs` | idem |
| ISO/IEC 27002 8.25, 8.28 | SBOM CycloneDX, tests automatisés, CI | `scripts/sbom.py`, `.github/workflows/ci.yml` | — |
