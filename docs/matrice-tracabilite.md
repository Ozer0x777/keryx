# Matrice de traçabilité (exigence → fonction → code → test)

Les références d'exigence sont reprises du plan de projet. Les normes ISO étant payantes, leur texte exact n'a pas été consulté : les renvois qui les concernent sont à confronter à la norme avant toute homologation. Les documents ETSI GS ISI sont publics et ont été lus (ISI 002 V1.2.1).

| Exigence | Fonction | Code | Test |
|---|---|---|---|
| PDIS IV.2.1.w | Ticket pré-rempli depuis l'alerte Wazuh | `ingest.py` | `test_ingest.py` |
| PDIS IV.2.1.aa, IV.2.2.s | Alerte brute conservée avec empreinte | `ingest.py`, `models.RawAlert` | `test_ingest.py` |
| PDIS IV.2.1.q | Qualification obligatoire avant réponse | `workflow.py`, `api.qualify` | `test_workflow_audit.py` |
| PDIS IV.2.1.e, r, s | Grille de gravité par client ; délais cibles (SLA) par client | `severity.py`, `sla.py`, `routes_admin.clients_patch` | `test_workflow_audit.py`, `test_admin.py`, `test_work.py` |
| PDIS IV.2.1.bb | Registre chronologique par client, export CSV | `routes_reports.registry` | `test_reports.py` |
| PDIS IV.2.1.y | Export IODEF (contrôle structurel) ; classification ETSI GS ISI 002 et export IODEF 2.0 « ETSI ISI » (clause 7.4) | `api.export_iodef`, `iodef.py`, `isi.py`, `routes_isi.py`, `IsiPanel.jsx` | `test_reports.py`, `test_isi.py`, `26-etsi-isi.mjs` |
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
| PRIS VI.2.4 | Conservation, restitution, destruction des pièces | `api.lifecycle` | `test_attachments.py`, `test_fixes_revue2.py`, `test_revue3_correctifs.py` (restituée puis détruite) |
| PRIS IV.3.q | Quarantaine des codes malveillants, ré-archivée avec mot de passe | `attachments.py` | `test_attachments.py` |
| Plan : stockage objet ; PDIS IV.3.3 | Pièces dans un stockage S3 de l'UE, chiffrées avant envoi | `s3store.py`, `attachments.py` | `test_s3.py` |
| ISO/IEC 27035-1 | Cycle de vie des incidents, liens et fusion, mesure des délais | `workflow.py`, `routes_work.py`, `routes_reports.py` | `test_workflow_audit.py`, `test_work.py`, `test_reports.py` |
| RFC 6238, 9106 | TOTP, Argon2id, enrôlement du TOTP par le titulaire, code d'activation à usage unique | `security.py`, `api.enroll_*` | `test_access.py`, `test_unit.py`, `test_enrollment.py`, `15-enrolement.mjs` |
| W3C WebAuthn ; plan : clés FIDO2 en option | Clés de sécurité comme second facteur | `routes_webauthn.py`, `webauthn.js` | `test_webauthn.py`, `50-webauthn.mjs` |
| PDIS IV.3.9.d ; RFC 6749, 7636, 9700 ; OIDC Core | SSO Keycloak : code + PKCE, jeton vérifié, liaison par courriel vérifié | `oidc.py`, `routes_oidc.py` | `test_oidc.py`, `60-sso.mjs` |
| RFC 6265, ASVS V7 | Sessions : cookie HttpOnly, CSRF, rotation, inactivité | `api.py` | `test_access.py` |
| RFC 7970, 8727 | Export IODEF JSON (sous-ensemble contrôlé) | `iodef.py` | `test_reports.py` |
| RFC 3161 | Horodatage de confiance des pièces et du point de contrôle d'audit (autorité locale en test, à choisir en production) | `timestamping.py`, `routes_timestamp.py`, `Stamps.jsx` | `test_timestamp.py`, `70-horodatage.mjs` |
| PDIS IV.2.1.aa ; PRIS VI.5.3.c ; ISO/IEC 27037 ; ADR-0021 | Contexte Wazuh, désactivé par défaut : lien vers l'alerte (équipe seulement), lecture de 5/10/15 événements du même agent dans l'indexeur, conservation à la demande comme pièce interne (SHA-256, registre de collecte). **Essayé contre un faux indexeur seulement, pas contre un vrai Wazuh** | `wazuh_context.py`, `routes_wazuh.py`, `api.get_ticket`, `WazuhContext.jsx`, `Ticket.jsx` | `test_wazuh_context.py`, `95-contexte-wazuh.mjs` |
| PDIS IV.3.8.g ; IV.3.9.d à h | Contexte Wazuh : jamais pour le client ni pour l'Admin, jamais un autre client, jamais un autre agent (même si l'indexeur le renvoie) | `routes_wazuh.team_guard`, `wazuh_context.fetch` | `test_wazuh_context.py` (`test_roles_et_cloisonnement`, `test_agent_different_…`, `test_lien_de_l_alerte_pour_l_equipe_seulement`) |
| ISO/IEC 27002 8.24 ; ADR-0006, ADR-0021 | Compte de lecture de l'indexeur chiffré au repos, jamais renvoyé ni journalisé ; effacé si l'adresse change | `routes_admin.apply_wazuh`, `security.SecretBox` | `test_wazuh_context.py` (`test_reglages_admin_…`, `test_identifiants_jamais_exposes_ni_journalises`, `test_changer_l_adresse_…`) |
| OWASP ASVS 5.0 (requêtes forgées côté serveur, numéro non revérifié) ; ADR-0021 | Règle de sortie vers l'indexeur : HTTPS, adresses de boucle locale, de lien local et de métadonnées refusées, contrôle des adresses résolues, pas de redirection, délai et taille bornés | `wazuh_context.parse_indexer_url`, `address_refusal`, `resolve`, `_connect` | `test_wazuh_context.py` (`test_adresse_d_indexeur_refusee`, `test_regle_de_sortie_…`, `test_nom_qui_resout_…`, `test_erreurs_de_l_indexeur_…`) |
| PDIS IV.3.9.c | Lecture et conservation du contexte Wazuh tracées sans le contenu ; compteurs de la file servis sans doubler l'entrée `ticket.list` à chaque relevé | `routes_wazuh.py`, `api.ticket_counts`, `Tickets.jsx` | `test_wazuh_context.py`, `test_work.py` (`test_compteurs_de_la_file_…`) |
| Demande de l'utilisateur (22/11/2026), sans exigence source dans cette matrice ; outille PDIS IV.2.1.q et PRIS IV.3.q ; **dérogation à « aucun service externe »**, ADR-0022 | Recherche d'une empreinte (SHA-256, SHA-1) sur VirusTotal depuis une pièce, une preuve externe, une alerte ou une saisie ; seule l'empreinte sort, jamais un fichier ; « inconnu » jamais présenté comme sain. **Essayé contre un faux serveur seulement, pas contre le vrai VirusTotal** | `virustotal.py`, `routes_virustotal.py`, `VirusTotal.jsx`, `web/src/virustotal.js` | `test_virustotal.py`, `web/tests/virustotal.test.mjs`, `96-virustotal.mjs` |
| PRIS VI.5.3.d ; ISO/IEC 27037 ; PDIS IV.3.9.c | Chaque recherche VirusTotal inscrite au registre `hash_lookups`, au registre des actions (interne), à l'audit et à la chaîne de possession de la pièce ; un échec n'inscrit que l'audit | `routes_virustotal.vt_lookup`, `models.HashLookup` | `test_virustotal.py` (`test_empreinte_d_une_piece_…`, `test_erreurs_de_virustotal_…`, `test_echec_sur_une_piece_…`) |
| PDIS IV.3.8.g ; IV.3.9.d à h | Recherche VirusTotal : jamais pour le client ni pour l'Admin, jamais un autre client ; la vue client de la fiche n'en porte aucune trace | `routes_virustotal.team_guard`, `api.get_ticket` | `test_virustotal.py` (`test_roles_et_cloisonnement`, `test_vue_client_…`, `test_cle_reservee_…`) |
| ISO/IEC 27002 8.24 ; ADR-0006, ADR-0022 | Clé d'API VirusTotal par utilisateur, chiffrée au repos, jamais renvoyée, journalisée ni auditée ; effacée si le compte quitte l'équipe | `routes_virustotal.vt_key_set`, `security.SecretBox`, `routes_admin.users_patch` | `test_virustotal.py` (`test_cle_chiffree_…`, `test_cle_de_forme_invalide_…`, `test_cle_effacee_…`) |
| ADR-0022 (sortie bornée ; aucun numéro ASVS cité, absent de cette matrice) | Appel vers VirusTotal : hôte fixe, HTTPS, pas de redirection, pas de mandataire d'environnement, délai et taille bornés, texte de la réponse assaini, interrupteur d'instance, limites de débit | `virustotal.Client`, `virustotal.summarize`, `routes_virustotal.enabled_guard` | `test_virustotal.py` (`test_erreurs_de_virustotal_…`, `test_texte_hostile_assaini`, `test_adresse_de_base_…`, `test_aucun_mandataire_…`, `test_interrupteur_…`, `test_limite_de_debit_…`) |
| WCAG 2.1 A/AA (base du RGAA) | Contrôle automatisé axe-core sur 19 écrans de 3 rôles. Ne remplace pas un audit RGAA complet | `e2e/scenarios/90-accessibilite.mjs` | idem |
| Plan : historique des versions du corps du ticket | Versions précédentes, auteur et date | `routes_work.body_history`, `Ticket.jsx` | `test_plan_manques.py`, `25-plan.mjs` |
| Plan : enrichissement MITRE niveau 3 et validation par le référentiel | Propositions de table, identifiants validés contre ATT&CK importé | `routes_ops.mitre_suggestions`, `api.set_mitre` | `test_plan_manques.py` |
| PRIS VI.2.4 ; plan : limite de pièce configurable par client | Taille maximale 1 à 20 Mo par client | `api.upload_attachment`, `routes_admin.clients_patch` | `test_plan_manques.py` |
| Plan : langue (i18n prévue dès le départ) | Mécanisme `t()` FR/EN, écrans principaux traduits | `web/src/i18n.js`, `i18n.en.js` | `80-langues.mjs` |
| ISO/IEC 27002 8.25, 8.28 | SBOM CycloneDX, tests automatisés, CI | `scripts/sbom.py`, `.github/workflows/ci.yml` | — |
