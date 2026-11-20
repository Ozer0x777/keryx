# ADR-0006 — Chiffrement des secrets TOTP au repos

- **Statut** : accepté (20/11/2026)
- **Décision** : les secrets TOTP sont chiffrés en AES-256-GCM (bibliothèque `cryptography`) avec une clé maîtresse `KERYX_SECRET_KEY` (32 octets, base64) fournie par l'environnement, jamais stockée en base. Le contexte `totp:<id utilisateur>` est passé en données associées : un secret copié d'un compte à l'autre ne se déchiffre pas. Format versionné `v1:` pour permettre une rotation de clé.
- **Pourquoi** : un vol de la base (sauvegarde, copie SQLite) ne doit pas suffire à générer des codes 2FA. Les mots de passe et codes de secours restent hachés (Argon2id / SHA-256), seul le secret TOTP doit être réversible.
- **Exigences** : RFC 6238 §5.1 (protection du secret partagé) ; OWASP ASVS 5.0 chap. 11 (cryptographie) et 6 (authentification) ; ISO/IEC 27002:2022 8.24 ; RGS B1 (AES-256, GCM).
- **Limite** : la clé maîtresse vit dans l'environnement du conteneur. En production : secret Docker/Kubernetes ou HSM ; procédure de rotation à écrire.
