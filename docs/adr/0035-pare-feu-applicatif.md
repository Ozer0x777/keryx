# ADR-0035 : pare-feu applicatif Coraza et OWASP CRS dans le kit Docker

- **Statut** : accepté (28/11/2026), décision du mainteneur (feuille de route, section 5 : le pare-feu applicatif
  d'abord, utile à tous les déploiements).
- **Contexte** : PDIS IV.3.13.g demande un pare-feu applicatif devant le portail web. Le kit Docker n'avait que Caddy,
  qui borne les corps de requête et relaie, sans filtrage applicatif. L'ADR-0027 avait retenu Coraza et l'OWASP Core
  Rule Set devant chaque portail ; le mode tout-en-un, produit principal, n'en avait pas.
- **Décision** :
  1. **Composant** : le module coraza-caddy (v2.6.2 : Coraza 3.8.1, OWASP CRS 4.25.0 embarqué), compilé dans Caddy par
     le kit (`deploy/docker/caddy-image`, xcaddy, images officielles de Caddy épinglées par empreinte, modules Go
     vérifiés par la base de sommes publique de Go). Aucun composant de plus : le pare-feu est dans le reverse proxy
     déjà présent. Écartés : ModSecurity (fin de support de la version 2 par Trustwave en 2024, module nginx séparé),
     un pare-feu applicatif dans Keryx lui-même (il ne protégerait pas d'une requête qui casse le serveur avant le
     code de Keryx).
  2. **Modes** (`KERYX_WAF`) : `blocage` par défaut (403 au-delà du seuil d'anomalie du CRS), `detection` (journalise
     sans bloquer), `off` (dépannage). Niveau de paranoïa 1, seuil d'anomalie par défaut du CRS (5).
  3. **Démarche** : la suite e2e complète (454 contrôles) a d'abord été jouée au travers du pare-feu en mode détection
     (`E2E_WAF=detection`) : 22 déclenchements, dont 5 chemins qui auraient été bloqués, tous des faux positifs. Les
     réglages ci-dessous les traitent ; puis la suite a été rejouée en mode blocage, devenu le défaut. La CI joue
     désormais la suite e2e au travers du pare-feu en mode blocage, avec un scénario qui vérifie que les attaques
     courantes sont refusées (`99-pare-feu.mjs`).
  4. **Contenu de sécurité par nature** : Keryx reçoit et stocke des alertes, des journaux, des commandes, des
     indicateurs de compromission, des adresses de connecteurs. Le corps des écritures (POST, PUT, PATCH) sur
     l'ingestion, les tickets, l'administration, la politique des clients, la table MITRE et les modèles n'est pas
     inspecté : le CRS y verrait une attaque à chaque alerte de type « injection SQL » ou « PowerShell », et une alerte
     bloquée serait perdue. Ces requêtes portent une clé d'API ou une session et un jeton CSRF ; Keryx les valide et
     les assainit lui-même (HTML assaini côté serveur, requêtes SQL paramétrées, CSP stricte). L'adresse, la chaîne de
     requête et les en-têtes restent inspectés sur ces chemins, et le corps des routes de connexion, de second facteur
     et de SSO reste inspecté.
  5. **Recherche** : le texte cherché (`q`) de la file et de la recherche de liens est souvent lui-même un indicateur ;
     il est retiré des règles d'injection, pour ces trois chemins exacts seulement.
  6. **Hôte en adresse IP** : la règle 920350 est retirée, le kit permettant l'accès par adresse IP.
  7. **Corps inspectés** : en mémoire, 2,5 Mio au plus (Caddy borne déjà chaque requête) ; pièces jointes et référentiel
     ATT&CK hors inspection (chemins de l'alinéa 4 ; les pièces passent par l'antivirus). Réponses non inspectées.
- **Limites** : le site de Keycloak (profil `sso`) n'est pas derrière le pare-feu (non essayé contre Keycloak). Le
  portail séparé par client (ADR-0027) aura le même pare-feu devant chaque portail. Le niveau de paranoïa 2 n'a pas été
  essayé. Les règles retirées le sont par chemin, jamais pour tout le site.
- **Exigences** : PDIS IV.3.13.g ; OWASP Core Rule Set 4 ; ANSSI, recommandations pour la sécurisation des sites web
  (filtrage applicatif en frontal).
- **Tests** : `E2E_WAF=blocage node run.mjs` (CI) et `E2E_WAF=detection` pour relever de nouveaux faux positifs (le
  harnais résume les règles déclenchées par chemin) ; validation du `Caddyfile` du kit dans les trois modes.
