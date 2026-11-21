# Keryx — éléments pour le dossier d'homologation

*État au 21/11/2026, version 0.7.0. Ce document **n'est pas** une homologation, un audit ni un test d'intrusion : il rassemble ce que Keryx fournit à une commission d'homologation, avec ce qui a été réellement vérifié et ce qui reste à décider ou à faire faire par un tiers.*

## 1. Système décrit
- **Rôle** : gestion des incidents de sécurité alimentée par Wazuh (tickets, registres, preuves, notifications, rapports).
- **Composants** : application web (FastAPI + interface React servie par l'application), base de données (SQLite pour les essais, PostgreSQL en production), stockage des pièces (disque ou stockage objet S3 chiffré avant envoi), antivirus ClamAV (optionnel), SMTP (optionnel), annuaire OpenID Connect Keycloak (optionnel), autorité d'horodatage RFC 3161 (optionnelle), export syslog vers Wazuh (optionnel).
- **Flux entrants** : alertes Wazuh (HTTPS, clé d'API par manager et par client) ; navigateurs des utilisateurs (HTTPS derrière un proxy TLS). **Flux sortants** : SMTP, ClamAV, Keycloak, stockage objet, autorité d'horodatage, syslog ; tous désactivés par défaut et configurables.
- **Hébergement visé** : UE, sans service externe obligatoire (décision du plan).
- **Rôles** : Admin (sans accès au contenu des tickets), Manager, Analyste, Client (cloisonnés par client).

## 2. Données traitées
Alertes de sécurité (adresses IP, noms d'hôtes, journaux bruts pouvant contenir des données personnelles), preuves déposées, commentaires, identités des utilisateurs, journal d'audit. Marquage TLP 2.0 par ticket et par pièce. **Durées de conservation à valider avec le DPO** (défauts : 12 mois pour les alertes brutes des tickets clos, 6 mois minimum ; tickets et registres sur la durée de la convention).

## 3. Mesures de sécurité en place
Voir `docs/matrice-tracabilite.md` (exigence → fonction → code → test) et les ADR 0001 à 0020. Synthèse :

| Domaine | Mesures |
|---|---|
| Authentification | Argon2id, TOTP obligatoire (secret chiffré AES-256-GCM, anti-rejeu), codes de secours, clés WebAuthn en option, SSO OIDC (PKCE, jeton vérifié, liaison par courriel vérifié), activation du compte par code à usage unique, verrouillage après échecs, limites de débit par IP et par identifiant (partagées en base avec PostgreSQL) |
| Sessions | Cookie HttpOnly/SameSite, jeton CSRF en double soumission sur toute route qui modifie, rotation à l'élévation, expiration absolue et par inactivité |
| Autorisation | Cloisonnement par client dans la couche d'accès (un ticket d'un autre client est « introuvable »), Admin sans accès au contenu (détails d'audit masqués), contrôle de rôle avant validation du corps |
| Données | HTML assaini côté serveur (liste blanche), CSP stricte sans source externe, images ré-encodées, archives jamais décompressées, quarantaine chiffrée, empreintes SHA-256, chaîne de possession, horodatage RFC 3161 optionnel |
| Traçabilité | Journal d'audit chaîné et scellé (HMAC), consultable, point de contrôle exportable et horodatable, export syslog RFC 5424, registre des actions par ticket |
| Exploitation | Migrations versionnées (testées sur base remplie), sauvegarde chiffrée par blocs (AES-GCM) avec restauration vérifiée, SBOM CycloneDX, dépendances figées avec empreintes, intégration continue |

## 4. Ce qui a été vérifié (reproductible)
- **Tests automatisés** : `python -m pytest` (201 réussis, 8 ignorés faute d'environnement) ; `python scripts/pg_tests.py` sous PostgreSQL 16.2 (201 réussis). Dont `tests/test_security_surface.py` : toutes les routes découvertes automatiquement (96) exigent une authentification sauf une liste justifiée, toutes celles qui modifient exigent le jeton CSRF, aucune route d'administration n'est atteignable par un autre rôle, en-têtes de sécurité et cookies contrôlés, pas d'énumération de comptes.
- **Parcours navigateur** (Chrome sans tête, base temporaire) : `cd e2e && E2E_KEYCLOAK=http://localhost:8180 node run.mjs` (plus de 100 contrôles : parcours de chaque rôle, mise en page, traduction, accessibilité axe-core sur 19 écrans).
- **Analyse dynamique OWASP ZAP** (authentifiée, 5 min d'analyse active) : voir `dast-zap.md` ; un constat réel corrigé (CSP), un défaut de forme corrigé (chemins de fichiers), un faux positif démontré et verrouillé par test.
- **Essais contre de vrais composants** : Keycloak 26.4 (SSO complet, déconnexion unique), PostgreSQL 16.2, Garage 1.0.1 (serveur S3 qui vérifie les signatures), FreeTSA (autorité d'horodatage publique, jeton revérifié par `openssl ts -verify`). Non testé : un vrai ClamAV, un vrai manager Wazuh, une clé WebAuthn physique, une autorité d'horodatage qualifiée eIDAS, un déploiement HTTPS réel derrière proxy.

## 5. Risques résiduels et limites connues
- Sans SMTP ni adresse courriel, l'Admin connaît le code d'activation d'un nouveau compte et pourrait l'enrôler à sa place (ADR-0011).
- Une session fermée côté Keycloak reste valable dans Keryx jusqu'à son expiration (pas de déconnexion initiée par Keycloak, ADR-0017).
- Le contenu des pièces sur disque n'est pas chiffré par Keryx (le stockage objet l'est) ; compter sur le chiffrement du volume.
- Sans `KERYX_SECRET_KEY`, 2FA, sauvegardes et pièces chiffrées sont définitivement perdus : sa conservation séparée est une exigence d'exploitation.
- Écart à valider avec un destinataire : l'export ETSI ISI utilise `AdditionalData` pour un incident individuel (ADR-0020).
- Le contrôle IODEF est structurel, pas contre le schéma officiel complet.
- Les alertes d'un manager Wazuh muet ne sont signalées qu'à l'administrateur (bandeau), pas notifiées.

## 6. À décider ou fournir par l'organisation
Durées de conservation (DPO) ; autorité d'horodatage (qualifiée eIDAS, dans l'UE) ; hébergeur et proxy TLS (TLS 1.2 minimum) ; politique de mots de passe et de rotation des clés d'API ; configuration MFA du realm Keycloak ; stratégie de sauvegarde (fréquence, lieu, test de restauration) ; supervision de Keryx lui-même ; niveau de sécurité visé (PRIS substantiel, compatible élevé) et commission d'homologation.

## 7. Prestations externes à commander
1. **Audit d'accessibilité RGAA** : voir `rgaa.md`.
2. **Test d'intrusion** : voir `cahier-test-intrusion.md`.
3. **Audit de configuration** du déploiement réel (proxy TLS, base, système, sauvegardes).
4. **Décision d'homologation** par l'autorité désignée, sur la base de ce dossier, des rapports ci-dessus et d'une analyse de risques propre à l'organisation (non fournie ici).
