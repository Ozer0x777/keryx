# ADR-0005 — Évolutions du schéma par migrations Alembic

- **Statut** : accepté (20/11/2026)
- **Décision** : le schéma n'est plus créé au démarrage. Toute évolution passe par une migration Alembic versionnée (`migrations/versions/`), appliquée par `alembic upgrade head` au lancement du conteneur. `KERYX_AUTO_CREATE_SCHEMA=true` reste réservé aux tests. Mode `render_as_batch` pour que les mêmes migrations fonctionnent sous SQLite (tests) et PostgreSQL (production).
- **Pourquoi** : une base de production ne doit jamais être modifiée sans trace ni retour arrière possible ; `alembic check` dans les tests détecte un modèle modifié sans migration.
- **Procédure** : sauvegarde de la base → `alembic upgrade head` → vérification → en cas d'échec, restauration (les migrations descendantes ne remplacent pas une sauvegarde).
- **Exigences** : ISO/IEC 27002:2022 8.32 (gestion des changements), 8.13 (sauvegarde), 8.25 (cycle de développement sécurisé) ; PDIS IV.3.9 (maîtrise des modifications du système).
- **Limite** : migrations testées sous SQLite uniquement ; à rejouer sur PostgreSQL avant la première mise en production.
