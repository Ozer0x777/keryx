# ADR-0001 : Stack technique

- **Statut** : accepté (20/11/2026)
- **Décision** : Python + FastAPI, SQLAlchemy 2, Argon2id (argon2-cffi), TOTP (pyotp), nh3. Bibliothèque standard uniquement côté manager Wazuh.
- **Pourquoi** : même langage que les intégrations Wazuh ; API documentée automatiquement (OpenAPI) ; bibliothèques mûres pour RFC 6238 et RFC 9106 ; nh3 remplace bleach (déprécié).
- **Exigences** : ASVS 5.0 V1, V6 ; RFC 6238 ; RFC 9106 ; ISO/IEC 27002:2022 8.25, 8.28.
- **Note** : développé et testé sous Python 3.13, cible 3.12 (Dockerfile).
