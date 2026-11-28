# Feuille de route

*In English: planned work for the next twelve months, in priority order. No date is promised; security fixes always
come first (`SECURITY.md`).*

État au 28/11/2026, version 0.12.0. Les priorités viennent des retours d'usage, en premier lieu l'essai sur une
préproduction Wazuh réelle (188 alertes reçues sur 188, 63 tickets). Une idée nouvelle se propose en issue ; un
choix technique passe par un ADR (`GOVERNANCE.md`).

## 1. Valider contre de vrais composants (priorité haute)

Plusieurs fonctions n'ont été essayées que contre les faux serveurs des tests (README, « Limites connues ») :

- contexte Wazuh contre un vrai indexeur et un vrai tableau de bord (ADR-0021) ;
- recherche VirusTotal contre le vrai service (ADR-0022) ;
- intégration sur un cluster Wazuh à plusieurs nœuds ;
- astreinte contre de vrais services (serveur de messagerie, Mattermost, Teams) et battement de cœur contre un vrai
  manager Wazuh (règle 119990, tâche planifiée, second bloc d'intégration ; ADR-0032).

Chaque essai réel donne lieu à une correction ou à une note dans la documentation. Fait : le parc d'agents contre
le manager de la préproduction (Wazuh 4.14.10), corrigé dans la 0.12.0.

## 2. Aide au triage (priorité haute)

- Table MITRE ATT&CK fournie pour des règles Wazuh courantes qui arrivent sans technique, chargée par l'équipe
  (`add-mitre`) : Keryx ne devine jamais une technique (`CONTRIBUTING.md`, règle 5).
- Grille de criticité initiale : exceptions par règle pour les changements sensibles (groupes, ACL, PowerShell) que
  le niveau Wazuh sous-estime.
- Séparation nette des tickets d'essai et des vrais tickets.

## 3. Conformité documentée

- Couverture des exigences PDIS (`docs/conformite/couverture-pdis.md`) : écarts du logiciel corrigés dans la 0.10.0,
  puis fichiers chiffrés ou non analysables et indicateurs de capacité dans la 0.11.0 ; restent le portail par
  client et le pare-feu applicatif (section 5 et ADR-0027).
- Couverture du référentiel PRIS v3.2 (`docs/conformite/couverture-pris.md`) : écarts du logiciel corrigés le
  27/11/2026 ; restent partiels le registre des actions sur une ressource du SI cible et le retour d'expérience par
  rubriques.

## 4. Robustesse et exploitation

Fait le 28/11/2026 : déconnexion demandée par Keycloak (ADR-0017), exports IODEF validés contre le schéma de la
RFC 8727, PDF des rapports produits par le serveur (ADR-0036). Restent les essais réels de la section 1.

## 5. Portail par client, pare-feu applicatif, disponibilité (mis de côté le 27/11/2026)

Seuls écarts PDIS du logiciel restants. Ordre recommandé : d'abord le pare-feu applicatif (Coraza et l'OWASP CRS
dans le Caddy du kit, en profil optionnel puis par défaut, après passage de toute la suite e2e), utile à tous ; la
disponibilité par une sonde extérieure sur `/healthz` (un logiciel ne mesure pas ses propres pannes), documentée
depuis la 0.12.0 (`docs/deploiement-docker.md`, matrice des flux, ligne 21) ;
le portail séparé par client (ADR-0027, `docs/conception/portail-par-client.md`) quand un déploiement visant la
qualification se présente, ses étapes 1 et 5 (projection client unique, modes) pouvant être faites avant sans
changement visible. Le mode tout-en-un reste le produit principal.

## Souhaité, selon les moyens

Audit d'accessibilité RGAA et test d'intrusion par un tiers (`docs/homologation/`) : à faire faire quand un
utilisateur ou un financement le permet.

## Propositions (non planifiées)

Idées relevées à l'usage, à discuter avant toute décision : elles ne sont pas inscrites au plan.

- **Envoi des alertes par lots depuis le manager.** Le manager Wazuh lance le script d'intégration une fois par
  alerte (environ 0,26 s chacune en préproduction, une connexion TLS par alerte), soit quelque 14 000 alertes par
  heure au plus ; une rafale plus rapide est livrée en retard (30 minutes mesurées, rapport du 27/11/2026). Piste :
  un relais sur le manager qui regroupe les alertes et les envoie par lots à une route d'ingestion acceptant
  plusieurs alertes, en gardant le dédoublonnage et l'alerte brute de chacune.
- **Signaler une alerte manquante.** Le manager ne transmet pas une alerte de plus de 64 Kio, sans aucune trace
  (observé en préproduction) ; rien ne le montre dans Keryx. Piste : repérer les trous dans la suite des alertes
  reçues d'un manager (identifiants ou compteurs Wazuh, à vérifier selon la version), ou recevoir du manager le
  nombre d'alertes produites pour le comparer au nombre reçu ; afficher l'écart dans « État du système ».
