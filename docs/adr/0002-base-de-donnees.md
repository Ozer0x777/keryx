# ADR-0002 — SQLite pour les tests, PostgreSQL en production

- **Statut** : accepté (20/11/2026)
- **Décision** : SQLite (mode WAL, clés étrangères actives) pour le développement et les tests ; PostgreSQL en production. Passage par simple changement de `KERYX_DATABASE_URL`.
- **Pourquoi** : zéro installation pour les premiers tests ; SQLite n'accepte qu'une écriture à la fois, ce qui devient bloquant avec plusieurs analystes et une ingestion continue.
- **Écart connu** : le MVP crée le schéma par `create_all`. Les migrations Alembic restent à mettre en place avant tout déploiement (exigence de traçabilité des changements, ISO/IEC 27002:2022 8.32).
- **Exigences** : PDIS IV.2.1.cc (capacité de stockage suivie), ISO/IEC 27002:2022 8.13 (sauvegardes, à traiter au déploiement).
