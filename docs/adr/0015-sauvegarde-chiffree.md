# ADR-0015 — Sauvegarde chiffrée

- **Statut** : accepté (20/11/2026) ; PostgreSQL à traiter avec la bascule de la base
- **Décision** : `keryx backup` produit une archive unique (copie cohérente de la base SQLite par l'API de sauvegarde en ligne, pièces, manifeste d'empreintes SHA-256) chiffrée par blocs de 1 Mio en AES-256-GCM, dans la construction STREAM (compteur et indicateur de dernier bloc dans le nonce) : toute modification, permutation ou troncature est détectée. Clé dérivée de `KERYX_SECRET_KEY` par HKDF-SHA256 avec un sel aléatoire. `keryx restore` exige un dossier vide, vérifie les empreintes, puis la chaîne d'audit.
- **Exigences** : PDIS IV.3.6 (sauvegardes protégées et testées) ; ISO/IEC 27002 8.13.
- **À savoir** : sans `KERYX_SECRET_KEY` la sauvegarde est indéchiffrable, et la base restaurée l'est aussi (secrets TOTP chiffrés avec la même clé). La conserver séparément, hors de la sauvegarde. Une restauration doit être répétée régulièrement : c'est le seul test qui prouve que la sauvegarde sert.
