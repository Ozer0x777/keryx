# ADR-0004 — Journal d'audit chaîné par empreintes

- **Statut** : accepté (20/11/2026), précisé par ADR-0007 (scellement HMAC + point de contrôle)
- **Décision** : chaque entrée contient l'empreinte SHA-256 de la précédente et de son propre contenu canonique ; `verify_chain` recalcule toute la chaîne. Chaque entrée est aussi exportable en syslog RFC 5424 (facilité 13 « log audit ») vers Wazuh.
- **Pourquoi** : rendre détectable toute modification ou suppression ; permettre au SOC de superviser son propre outil.
- **Limite** : un administrateur de la base peut réécrire toute la chaîne. L'export syslog vers un système tiers (Wazuh) et, plus tard, l'horodatage de confiance (RFC 3161) des têtes de chaîne réduisent ce risque.
- **Exigences** : PDIS IV.3.9.c ; ISO/IEC 27002:2022 8.15 ; recommandations ANSSI journalisation ; RFC 5424.
