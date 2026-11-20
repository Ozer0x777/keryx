# Modèle de données (v0.2)

Source de vérité : `keryx/models.py` ; évolutions uniquement par migration Alembic (ADR-0005).
Identifiants UUIDv7 (RFC 9562), dates en UTC (RFC 3339).

| Table | Rôle | Exigences |
|---|---|---|
| `tenants` | Client / commanditaire, compteur des références (`ACME-12`, incrément atomique), grille de gravité, contacts de notification | PDIS IV.3.8.g, IV.2.1.bb, IV.2.1.e/r/s, IV.2.3.g |
| `users` | Comptes, rôle, Argon2id, secret TOTP chiffré AES-256-GCM, codes de secours hachés, verrouillage (échecs TOTP), anti-rejeu, dernière connexion | PDIS IV.3.9, RFC 9106, RFC 6238, ADR-0006, ADR-0010 |
| `user_tenants` | Affectation utilisateur ↔ client (besoin d'en connaître) | PDIS IV.3.9.g, PRIS IV.3.d |
| `sessions` | Sessions en 2 étapes, jeton CSRF, expiration absolue et d'inactivité | RFC 6265, ASVS chap. 7 |
| `api_keys` | Clés d'ingestion Wazuh hachées, une par manager et par client | PDIS IV.3.10.e |
| `tickets` | Contenu minimal PDIS, criticité/gravité, verdict, TLP, MITRE + provenance, statut ISO 27035, synthèse (compromission initiale, chronologie, mode opératoire, périmètre, REX) | PDIS IV.2.1.w, q ; PRIS VI.5.3.e ; ISO/IEC 27035 |
| `raw_alerts` | Alertes Wazuh brutes, empreinte SHA-256, identifiant Wazuh (idempotence) | PDIS IV.2.1.aa, IV.2.2.s |
| `comments` | Commentaires internes ou visibles client | PDIS IV.2.3.l |
| `ticket_events` | Registre horodaté des actions du ticket (dont versions précédentes de la description) | PRIS VI.5.3.d |
| `notifications` | Registre des notifications (référence seule) et statut d'envoi SMTP | PDIS IV.2.3.g, h, j ; ADR-0009 |
| `mitre_mappings` | Table de correspondance règle/groupe → technique | Décision projet |
| `attachments` | Fichiers, images et preuves externes : SHA-256, registre de collecte, statut antivirus, cycle de vie, visibilité client | PRIS VI.5.3.c, VI.2.4 ; ISO/IEC 27037 ; ADR-0008 |
| `custody_events` | Chaîne de possession (dépôt, téléchargement + motif, restitution, destruction) | ISO/IEC 27037 ; RFC 3227 |
| `audit_log` | Journal d'audit en ajout seul, séquence continue, scellement HMAC | PDIS IV.3.9.c ; ISO 27002 8.15 ; ADR-0007 |
| `ticket_links` | Liens parent / lié / doublon entre tickets d'un même client | ISO/IEC 27035 (regroupement d'incidents) ; ADR-0012 |
| `templates` | Modèles de commentaire et de synthèse (communs ou par client) | Confort d'analyste ; HTML assaini comme tout contenu |
| `inbox` | Notifications dans l'interface : référence et nature de l'événement, sans détail | PDIS IV.2.3.g (par analogie, pas de détail) ; ADR-0012 |
| `saved_filters` | Filtres de liste enregistrés par utilisateur | Confort d'analyste |
| `crisis_entries` | Registre de crise : décisions, plan d'action, synthèse de crise | PRIS VI.5.5.1 ; ADR-0013 |
| `mitre_techniques` | Référentiel ATT&CK importé (STIX 2.1) : nom et tactiques | MITRE ATT&CK ; ADR-0014 |
Colonnes ajoutées : `tenants.retention_months`, `tenants.sla`, `api_keys.last_used_at`, `users.notif_prefs`, `tickets.crisis`, `tickets.crisis_started_at`, `notifications.attempts`.
