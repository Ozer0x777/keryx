# Cahier des charges du test d'intrusion de Keryx

*À remettre à un prestataire. Rédigé par l'équipe de développement : à compléter par le commanditaire (cadre juridique, calendrier, contacts, règles d'engagement).*

## Objectif
Évaluer la résistance de Keryx (application web et API) à un attaquant : externe sans compte, utilisateur authentifié d'un rôle donné cherchant à dépasser ses droits, et client cherchant à lire les données d'un autre client.

## Périmètre
- **Cible** : une instance de recette déployée comme en production (HTTPS, proxy TLS, PostgreSQL), version 0.7.0, avec données fictives.
- **Interfaces** : interface web (`/`), API (`/api/v1/*`, description : `/api/openapi.json`), ingestion Wazuh (`POST /api/v1/ingest/wazuh`, clé d'API), SSO OIDC (`/api/v1/auth/oidc/*`), WebAuthn (`/api/v1/auth/webauthn/*`).
- **Comptes fournis** : un Admin, un Manager (2 clients), un Analyste, un Client par client (2 clients au moins), avec leur second facteur ; une clé d'API d'ingestion par client ; un realm Keycloak de recette.
- **Hors périmètre** : l'infrastructure d'hébergement, Keycloak, Wazuh, ClamAV en tant que produits ; déni de service par saturation volumétrique.

## Points d'attention demandés
1. **Cloisonnement par client** : accès direct aux objets (tickets, pièces, jetons d'horodatage, notifications, filtres, modèles, liens) d'un autre client, par identifiant, par recherche, par export (CSV, rapports, IODEF), par le journal d'audit.
2. **Séparation des rôles** : l'Admin ne doit jamais lire le contenu des tickets ni des pièces ; le Client ne doit jamais voir un commentaire interne, une classification, un registre de crise, une échéance.
3. **Authentification** : contournement du second facteur, rejeu de code TOTP ou de code de secours, fixation de session, force brute (limites de débit), énumération de comptes, activation de compte (code d'activation), réinitialisation par l'Admin, SSO (état, nonce, PKCE, liaison de compte, jeton falsifié), WebAuthn.
4. **Sessions et CSRF** : durée, rotation, déconnexion, jeton CSRF sur toute route modifiante.
5. **Injection et contenu** : XSS stocké via l'éditeur riche, les commentaires, les titres d'alerte (données Wazuh hostiles), les noms de fichiers ; injection SQL ; injection de formules dans les exports CSV ; en-têtes et journaux (injection de lignes dans le journal d'audit et le syslog).
6. **Pièces jointes** : dépassement de taille, archives piégées, images piégées, type de contenu, téléchargement de pièces en quarantaine, parcours de chemins, contournement de l'antivirus.
7. **Ingestion** : clé d'API volée ou révoquée, alertes malformées ou volumineuses, déni de service applicatif, doublons concurrents.
8. **Cryptographie et secrets** : chiffrement des secrets TOTP, scellement du journal d'audit, sauvegardes chiffrées, objets chiffrés du stockage S3.
9. **Configuration** : en-têtes de sécurité, CSP, cookies, messages d'erreur, ressources statiques exposées.

## Livrables attendus
Rapport avec méthodologie, constats classés par gravité (CVSS), preuves reproductibles, recommandations, contre-visite après correction.

## Ce que l'équipe a déjà contrôlé (sans remplacer ce test)
`tests/test_security_surface.py` (authentification, CSRF, rôles, en-têtes sur toutes les routes découvertes automatiquement), `tests/test_access.py`, `tests/test_review_regressions.py`, tests de cloisonnement par fonctionnalité. Deux relectures de code ont corrigé 25 défauts (cloisonnement, concurrence, validation, fuite de contenu).
