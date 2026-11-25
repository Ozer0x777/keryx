# Sécurité de Keryx : ce qui est protégé, contre quoi, et pourquoi c'est suffisant

*In English: what Keryx protects, the threats it is designed against, the secure design principles applied, and the
assurance case. Report vulnerabilities as described in `SECURITY.md`.*

Ce document est l'argumentaire de sécurité du projet. Il s'appuie sur `docs/architecture.md` (composants et
frontières de confiance), les ADR (`docs/adr/`) et le dossier d'homologation (`docs/homologation/`). Il ne remplace
ni un test d'intrusion ni une analyse de risques propre à l'organisation qui déploie Keryx.

## 1. Ce que l'utilisateur peut attendre, et ce qu'il ne peut pas attendre

Keryx garantit, s'il est déployé selon `docs/deploiement-docker.md` :

- **Cloisonnement par client** : un utilisateur d'un client n'accède à aucune donnée d'un autre client ; un ticket
  d'un autre client répond « introuvable ».
- **Séparation des rôles** : l'Admin gère comptes et réglages sans lire le contenu des tickets ; le client ne voit
  que ce qui lui est destiné.
- **Authentification forte** : mot de passe haché en Argon2id et second facteur obligatoire (TOTP, ou clé WebAuthn),
  ou authentification unique OIDC.
- **Traçabilité infalsifiable sans détection** : toute action qui modifie un ticket, un compte ou un réglage est
  écrite dans un journal chaîné et scellé ; une modification casse la chaîne et se voit à la vérification.
- **Intégrité des preuves** : empreinte SHA-256, chaîne de possession, horodatage RFC 3161 en option.
- **Secrets chiffrés au repos** : secrets TOTP, mots de passe des connecteurs, clés VirusTotal en AES-256-GCM.

Keryx ne garantit pas, et ces points restent à la charge de l'exploitant :

- la sécurité du serveur, du réseau, du proxy TLS et des sauvegardes hors de Keryx ;
- la conservation de `KERYX_SECRET_KEY` à part : sans elle, secrets et sauvegardes sont perdus ; avec elle, un
  attaquant qui a aussi la base lit les secrets chiffrés ;
- le chiffrement des pièces stockées sur disque (le stockage objet l'est, le disque non : chiffrer le volume) ;
- la disponibilité : un seul processus, pas de haute disponibilité ;
- la qualification PDIS : le mode tout-en-un ne réalise pas l'architecture en zones (voir `ROADMAP.md`).

Les risques résiduels connus sont listés dans `docs/homologation/dossier-homologation.md`, section 5.

## 2. Modèle de menaces

| Acteur | Ce qu'il cherche | Point d'entrée |
|---|---|---|
| Attaquant externe | Accès aux incidents (données sensibles de plusieurs clients) | Page de connexion, API publique, route d'ingestion |
| Client malveillant ou compromis | Données d'un autre client, élévation de privilèges | Son compte légitime |
| Analyste ou Admin malveillant | Effacer ou modifier une trace, lire au-delà de son rôle | Son compte légitime, la ligne de commande |
| Alerte ou pièce piégée | Exécution de script (XSS), code dans un fichier, dépassement de ressources | Contenu des alertes Wazuh, pièces jointes, HTML des commentaires |
| Service externe compromis ou usurpé | Injection de données, vol de secrets | Réponses de Wazuh, VirusTotal, Keycloak, SMTP, S3 |
| Dépendance compromise | Code malveillant dans la chaîne d'approvisionnement | Paquets Python et npm, images Docker |

## 3. Principes de conception sécurisée appliqués

| Principe | Application dans Keryx |
|---|---|
| Moindre privilège | Rôles distincts ; Admin sans accès au contenu des tickets ; comptes de lecture seule pour Wazuh ; conteneurs sans root, sans capability, en lecture seule |
| Refus par défaut | Toute route exige une session, sauf une liste justifiée vérifiée par test (`tests/test_security_surface.py`) ; connecteurs externes désactivés par défaut |
| Médiation complète | Cloisonnement appliqué dans la couche d'accès aux données, pas dans l'interface ; rôle contrôlé avant la lecture du corps |
| Défense en profondeur | HTML assaini côté serveur et CSP stricte ; antivirus et quarantaine chiffrée ; journal scellé et export syslog |
| Économie de mécanisme | Une seule application ; bibliothèques reconnues pour la cryptographie ; aucun algorithme maison |
| Conception ouverte | Code public sous licence MIT ; sécurité qui ne repose sur aucun secret de conception |
| Valeurs sûres par défaut | TLS vérifié par défaut ; second facteur obligatoire ; redirections jamais suivies ; délais bornés |
| Séparation des privilèges | Élévation de session (rotation) ; actions sensibles confirmées ; clés d'API par client et par manager |
| Traçabilité | Journal chaîné et scellé, points de contrôle horodatables, registre des actions par ticket |
| Données non fiables | Entrées validées par schéma (Pydantic) ; tailles bornées avant l'application ; archives jamais décompressées ; images ré-encodées |

## 4. Argumentaire : pourquoi ces mesures suffisent

Pour chaque menace de la section 2, la mesure, et la preuve qu'elle fonctionne :

| Menace | Mesures | Preuve |
|---|---|---|
| Accès externe aux incidents | Argon2id, second facteur obligatoire, verrouillage et limites de débit, sessions HttpOnly et SameSite, CSRF en double soumission, expiration absolue et par inactivité | `tests/test_security_surface.py` (toutes les routes), scan OWASP ZAP authentifié (`docs/homologation/dast-zap.md`) |
| Fuite entre clients | Cloisonnement dans la couche d'accès ; test obligatoire pour chaque route qui touche un ticket (`CONTRIBUTING.md`, règle 3) | Tests de cloisonnement dans `tests/` pour chaque route |
| Abus d'un compte interne | Séparation des rôles ; journal chaîné (HMAC-SHA256) et points de contrôle ; détails masqués à l'Admin | Tests du journal (`tests/test_workflow_audit.py` : chaîne et infalsifiabilité) |
| Contenu piégé | Assainissement HTML par liste blanche côté serveur, CSP sans source externe, images ré-encodées, ClamAV, quarantaine chiffrée | Tests d'assainissement et des pièces (EICAR), contrôles CSP dans les parcours navigateur |
| Service externe usurpé | TLS 1.2 minimum et certificat vérifié par défaut, aucune redirection suivie, réponses validées et bornées, aucune donnée de ticket envoyée hors de Keryx sauf une empreinte à VirusTotal (désactivable) | Faux serveurs hostiles des tests (`tests/fake_*.py`) |
| Chaîne d'approvisionnement | Dépendances figées avec empreintes, pip-audit et npm audit bloquants, Dependabot, CodeQL, image signée (cosign) avec provenance et SBOM | CI (`.github/workflows/`), `docs/publication.md` |

## 5. Cryptographie

| Usage | Algorithme | Bibliothèque |
|---|---|---|
| Mots de passe | Argon2id (RFC 9106), sel aléatoire | `argon2-cffi` |
| Secrets au repos, sauvegardes | AES-256-GCM, clé de 256 bits, nonce aléatoire, contexte lié | `cryptography` |
| Journal d'audit | HMAC-SHA256 chaîné | bibliothèque standard Python |
| Preuves | SHA-256 | bibliothèque standard Python |
| Second facteur | TOTP (RFC 6238, HMAC-SHA1 imposé par le standard et les applications d'authentification ; HMAC-SHA1 n'a pas de faiblesse connue, contrairement à SHA-1 seul) ou WebAuthn | `pyotp`, `webauthn` |
| Transport | TLS 1.2 minimum, 1.3 préféré, échange de clés à confidentialité persistante ; terminé par Caddy | Caddy, `ssl` |
| Aléa | Générateur cryptographique du système | `secrets`, `os.urandom` |

SHA-1 n'est utilisé comme empreinte que pour interroger VirusTotal sur un fichier déjà identifié par Wazuh, jamais
comme garantie d'intégrité ; MD5 est refusé (ADR-0022). Les secrets (clé maîtresse, mots de passe des connecteurs)
viennent de l'environnement ou de la base chiffrée, jamais du code : ils se changent sans modifier Keryx.

## 6. Durcissement

En-têtes de sécurité et CSP stricte sans source externe, cookies `HttpOnly`, `Secure`, `SameSite`, taille des corps
bornée avant l'application, conteneurs sans root ni capability en système de fichiers en lecture seule, image de base
minimale, dépendances figées avec empreintes.
