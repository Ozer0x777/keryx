# ADR-0009 — Envoi des notifications par SMTP

- **Statut** : accepté (20/11/2026)
- **Décision** : à la création d'un ticket, une notification par contact du client est inscrite au registre (statut `en_attente`), puis envoyée en tâche de fond après la réponse à Wazuh. SMTP via la bibliothèque standard, TLS obligatoire (STARTTLS vérifié par le contexte par défaut, ou SMTPS). Le message ne contient que la référence et un lien. Statuts : `envoye`, `echec`, `non_envoye_smtp_absent`, `sans_destinataire`, chacun journalisé.
- **Pourquoi** : la notification ne doit jamais divulguer le contenu d'un incident sur un canal non maîtrisé ; l'ingestion Wazuh ne doit pas attendre le serveur de messagerie.
- **Exigences** : PDIS IV.2.3.g, h, j ; RFC 8314 (TLS pour la messagerie) ; RFC 5322.
- **Limite** : pas de nouvelle tentative automatique après un échec (visible dans le registre et l'audit).
