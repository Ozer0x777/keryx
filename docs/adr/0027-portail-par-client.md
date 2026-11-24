# ADR-0027 : Portail séparé par client, alimenté par la console

- **Statut** : proposé (24/11/2026), en attente de validation du mainteneur. Aucun code tant qu'il n'est pas accepté.
- **Contexte** : un seul Keryx sert l'équipe et les clients. PDIS IV.3.13.b demande une machine physique ou virtuelle
  par commanditaire pour le portail et son stockage, dans une zone d'échange distincte de la zone d'analyse
  (IV.3.8.b). Détail dans `docs/conception/portail-par-client.md`.
- **Décision proposée** :
  1. Un seul code, trois modes : `tout-en-un` (défaut, comportement actuel), `console` (zone d'analyse, équipe
     seulement), `portail` (zone d'échange, un seul client, rôle Client seulement).
  2. Le portail ne reçoit que la projection client, calculée par une fonction unique déjà utilisée par l'API du
     rôle Client.
  3. Tous les flux sont ouverts par la console (poussée des projections, rapatriement des saisies) ; aucune connexion
     de la zone d'échange vers la zone d'analyse.
  4. TLS mutuel entre console et portails, certificats signés par une autorité interne dédiée ; versions par objet
     contre le rejeu.
- **Options écartées** : un Keryx complet par client (la console et les données internes dans la zone exposée) ;
  un portail qui interroge la console (flux entrant dans la zone d'analyse) ; un portail sans base, mandataire de la
  console (même flux entrant, et le portail ne fonctionne plus si la console est coupée).
- **Exigences** : PDIS IV.3.13.b, IV.3.8.b, c, d, IV.3.13.c et g, lues et citées dans `docs/deploiement-docker.md` ;
  le reste du chapitre IV.3.13 est **à relire** avant acceptation.
- **Conséquences** : une VM, une base et un certificat par client à exploiter ; un délai (quelques secondes) entre
  une réponse du SOC et son affichage sur le portail ; le mode tout-en-un reste disponible et inchangé.
