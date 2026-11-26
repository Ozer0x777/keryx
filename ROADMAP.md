# Feuille de route

*In English: planned work for the next twelve months, in priority order. No date is promised; security fixes always
come first (`SECURITY.md`).*

État au 26/11/2026, version 0.9.0. Les priorités viennent des retours d'usage, en premier lieu l'essai sur une
préproduction Wazuh réelle (188 alertes reçues sur 188, 63 tickets). Une idée nouvelle se propose en issue ; un
choix technique passe par un ADR (`GOVERNANCE.md`).

## 1. Valider contre de vrais composants (priorité haute)

Plusieurs fonctions n'ont été essayées que contre les faux serveurs des tests (README, « Limites connues ») :

- parc d'agents Wazuh contre un vrai manager : champs de `/agents`, permissions RBAC du compte de lecture (ADR-0030) ;
- contexte Wazuh contre un vrai indexeur et un vrai tableau de bord (ADR-0021) ;
- recherche VirusTotal contre le vrai service (ADR-0022) ;
- intégration sur un cluster Wazuh à plusieurs nœuds ;
- astreinte contre de vrais services (serveur de messagerie, Mattermost, Teams) et battement de cœur contre un vrai
  manager Wazuh (règle 119990, tâche planifiée, second bloc d'intégration ; ADR-0032).

Chaque essai réel donne lieu à une correction ou à une note dans la documentation.

## 2. Aide au triage (priorité haute)

- Table MITRE ATT&CK fournie pour des règles Wazuh courantes qui arrivent sans technique, chargée par l'équipe
  (`add-mitre`) : Keryx ne devine jamais une technique (`CONTRIBUTING.md`, règle 5).
- Grille de criticité initiale : exceptions par règle pour les changements sensibles (groupes, ACL, PowerShell) que
  le niveau Wazuh sous-estime.
- Séparation nette des tickets d'essai et des vrais tickets.

## 3. Conformité documentée

- Couverture des exigences PDIS chapitre IV : statut et preuve vérifiée pour chaque exigence
  (`docs/matrice-tracabilite.md` étendue).

## 4. Robustesse et exploitation

- Déconnexion initiée par Keycloak (aujourd'hui, une session fermée dans Keycloak reste valable dans Keryx jusqu'à
  son expiration, ADR-0017).
- Validation de l'export IODEF contre le schéma officiel complet ; PDF des rapports produit côté serveur.

## 5. Portail par client (optionnel)

Séparer le portail client de la console d'analyse, une machine par client (PDIS IV.3.13.b), pour un prestataire qui
vise la qualification. ADR-0027 accepté le 26/11/2026 après lecture intégrale du référentiel : décisions et découpage
dans `docs/conception/portail-par-client.md`. Premières étapes, utiles aussi en tout-en-un : liste publiée des
exigences PDIS non couvertes par ce mode, actions demandées au client, traitement des fichiers chiffrés ou non
analysables. Le mode tout-en-un reste le produit principal.

## Souhaité, selon les moyens

Audit d'accessibilité RGAA et test d'intrusion par un tiers (`docs/homologation/`) : à faire faire quand un
utilisateur ou un financement le permet.
