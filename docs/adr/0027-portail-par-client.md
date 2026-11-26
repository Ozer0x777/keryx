# ADR-0027 : Portail séparé par client, alimenté par la console

- **Statut** : accepté (26/11/2026), par délégation du mainteneur, après lecture intégrale du référentiel PDIS v2.0
  (21/12/2017). Décisions détaillées dans `docs/conception/portail-par-client.md`, section 6 ; code dans l'ordre de
  la section 5.
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
- **Décisions** (questions ouvertes de la conception, tranchées le 26/11/2026) :
  1. poussée immédiate vers le portail ; la notification au client part après l'accusé de réception du portail (au
     plus 2 minutes d'attente) ; saisies du client rapatriées toutes les 15 secondes ;
  2. comptes des clients gérés dans la console par l'Admin, secrets créés et gardés sur le portail seulement
     (annuaire dédié, IV.3.13.c, distinct de celui de l'équipe, IV.3.9.d) ;
  3. SQLite pour le portail (un client, peu d'utilisateurs, moins de composants par VM), PostgreSQL possible ;
  4. le tout-en-un reste le mode par défaut, avec la liste publiée des exigences PDIS qu'il ne couvre pas (III.3) ;
  5. fichiers analysés aux deux bouts, archives chiffrées « non analysables » et isolées, journal de passage
     (IV.3.13.a) ;
  6. le client met à jour l'état des actions que l'équipe lui demande, pas le statut de l'incident (IV.2.3.l) ;
  7. pare-feu applicatif Coraza avec l'OWASP CRS devant chaque portail (IV.3.13.g) ;
  8. indicateurs du portail rapatriés par la console (IV.5.1.e, g) ;
  9. IPsec agréé, filtrage qualifié et relais de messagerie restent à l'infrastructure (IV.3.8.e, IV.3.10, IV.3.12).
- **Exigences** : référentiel PDIS v2.0 lu en entier ; IV.3.8.b à g, IV.3.9.c et d, IV.3.10, IV.3.12, IV.3.13.a à h,
  IV.2.3.g à l, IV.5.1.e et g, III.3 (voir le tableau de la conception, section 1). Reste à lire : le chapitre
  « Système d'échange » de la note technique [NT_ADMIN], avant l'étape 4.
- **Conséquences** : une VM, une base et un certificat par client à exploiter ; un délai (quelques secondes) entre
  une réponse du SOC et son affichage sur le portail ; le mode tout-en-un reste disponible et inchangé.
