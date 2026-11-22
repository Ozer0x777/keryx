# Fonctions et exigences

Chaque fonction de Keryx et les exigences auxquelles elle se rattache. La matrice détaillée (exigence, code, test) est dans `matrice-tracabilite.md`.

| Fonction | Exigences |
|---|---|
| Ingestion `POST /api/v1/ingest/wazuh`, clé d'API par manager et par client, idempotence et dédoublonnage 15 min | PDIS IV.3.8.g, IV.3.10.e, IV.2.1.w |
| Ticket pré-rempli (règles, équipements, identifiants, criticité, MITRE), alerte brute + SHA-256 | PDIS IV.2.1.w, aa ; IV.2.2.s |
| Criticité initiale (niveau Wazuh) / gravité qualifiée (grille par client) | PDIS IV.2.1.e, q, r, s |
| MITRE en cascade Wazuh → table → correction manuelle tracée | Décision projet, ISO 27035 |
| Cycle ISO 27035, qualification obligatoire, synthèse et REX obligatoire si Élevée/Critique | ISO/IEC 27035-1, PRIS VI.5.3.e, ISO 27002 5.27 |
| Interface web : liste, Kanban, ticket, portail client, administration | Maquettes validées |
| Rôles Admin/Manager/Analyste/Client, cloisonnement par client, admin sans accès au contenu | PDIS IV.3.8.g, IV.3.9.d à h, PRIS IV.3.d |
| Argon2id + TOTP obligatoire (secret chiffré) + codes de secours + anti-rejeu + limites de débit + clés de sécurité WebAuthn en option + SSO OpenID Connect (Keycloak) | RFC 9106, 6238, 6585 ; ADR-0006, 0010, 0016, 0017 |
| Session cookie HttpOnly/Secure/SameSite, rotation, CSRF, inactivité 30 min | RFC 6265, ASVS chap. 7 |
| HTML assaini (nh3, liste blanche) ; CSP sans source externe | ASVS chap. 1, 3 |
| Pièces jointes 20 Mo, images ré-encodées, registre de collecte, ClamAV + quarantaine, chaîne de possession, preuves externes | PRIS VI.5.3.c, VI.2.4 ; ISO/IEC 27037 ; RFC 3227 ; ADR-0008 |
| Notifications SMTP (référence + lien seulement) avec registre | PDIS IV.2.3.g, h, j ; ADR-0009 |
| Journal d'audit scellé HMAC, point de contrôle externe, export syslog | PDIS IV.3.9.c, ISO 27002 8.15, RFC 5424 ; ADR-0007 |
| Revue des comptes et des droits | PDIS IV.3.4.b |
| Export IODEF JSON (sous-ensemble) | RFC 7970, RFC 8727 |
| Classification ETSI GS ISI 002 (8 axes, dictionnaire de l'Annexe B) et export IODEF 2.0 recommandé par l'ETSI | PDIS IV.2.1.y ; ADR-0020 |
| Erreurs Problem Details, UUIDv7, dates RFC 3339 UTC, no-store, HSTS | RFC 9457, 9562, 3339, 9111, 6797 |
| Migrations Alembic | ISO 27002 8.32 ; ADR-0005 |
| Administration dans l'interface : comptes, clients (grille, SLA, rétention), clés d'API, MITRE, revue, état du système | PDIS IV.3.4.b, IV.3.9.d à h ; ADR-0011 |
| Recherche plein texte, vues, tri, affectation en masse, filtres enregistrés, modèles, liens et fusion, échéances (SLA), notifications dans l'interface | PDIS IV.2.1.e, r, s ; ADR-0012 |
| Pilotage : tableau de bord, registre par client (CSV), rapport périodique et d'incident imprimables | PDIS IV.2.1.bb |
| Mode crise (registre des décisions, plan d'action, synthèse) | PRIS VI.5.5.1 ; ADR-0013 |
| Journal d'audit consultable (contenu masqué à l'Admin), point de contrôle, import ATT&CK (STIX), rétention | PDIS IV.3.9.c, IV.2.2.w ; ADR-0014 |
| Horodatage de confiance RFC 3161 des pièces et du point de contrôle d'audit | RFC 3161 ; ISO/IEC 27037 ; ADR-0018 |
| Contexte Wazuh, désactivé par défaut et réglé par client : lien vers l'alerte dans le tableau de bord (équipe seulement), lecture de 5, 10 ou 15 événements du même agent dans l'indexeur, conservation à la demande comme pièce interne | PDIS IV.2.1.aa ; PRIS VI.5.3.c ; ADR-0021 |
| Recherche d'une empreinte (SHA-256, SHA-1) sur VirusTotal, disponible par défaut, clé d'API par utilisateur : depuis une pièce, une preuve externe, une alerte ou une saisie ; jamais d'envoi de fichier ; chaque recherche tracée. **Dérogation à « aucun service externe »** | PDIS IV.2.1.q, PRIS IV.3.q, PRIS VI.5.3.d ; ADR-0022 |
| Stockage objet S3 des pièces, chiffré avant envoi ; quarantaine en archive chiffrée | PRIS IV.3.q, VI.2.4 ; ADR-0019 |
| Sauvegarde chiffrée et restauration vérifiée | PDIS IV.3.6 ; ADR-0015 |
| Déploiement par conteneurs durci (un conteneur par service, profils, HTTPS dans les deux modes), matrice des flux | Fiche ANSSI-FT-082 R1 à R16 ; PDIS IV.3.8.d ; ADR-0023 |
