# ADR-0007 : Scellement HMAC du journal d'audit et point de contrôle externe

- **Statut** : accepté (20/11/2026), complète ADR-0004
- **Décision** : chaque entrée du journal porte un numéro de séquence continu et un sceau HMAC-SHA256 calculé sur (sceau précédent, contenu canonique, numéro). La clé HMAC est dérivée de `KERYX_SECRET_KEY` (jamais en base). Les écritures sont sérialisées (BEGIN IMMEDIATE sous SQLite, verrou consultatif sous PostgreSQL). `keryx checkpoint` produit un couple `séquence:sceau` à archiver hors de Keryx ; `keryx verify-audit --checkpoint` vérifie qu'aucune entrée antérieure n'a disparu ni changé.
- **Pourquoi** : la revue indépendante a montré qu'une simple chaîne SHA-256 peut être recalculée entièrement par quiconque a accès en écriture à la base, et qu'une troncature des dernières entrées passait inaperçue.
- **Exigences** : PDIS IV.3.9.c ; ISO/IEC 27002:2022 8.15 ; ANSSI recommandations journalisation ; RFC 5424 (export syslog, caractères de contrôle neutralisés).
- **Limite** : quiconque détient à la fois la base et la clé maîtresse peut réécrire la chaîne. Parades : export syslog en continu vers Wazuh, points de contrôle archivés hors ligne ; horodatage de confiance RFC 3161 envisagé en phase suivante.
