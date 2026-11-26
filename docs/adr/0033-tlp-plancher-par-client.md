# ADR-0033 : TLP plancher par client, fixé par le manager

- **Statut** : accepté (26/11/2026), décisions du mainteneur.
- **Contexte** : chaque ticket naissait en `TLP:AMBER` quel que soit le client, et un analyste pouvait le passer à
  n'importe quel niveau, `TLP:CLEAR` compris, à la qualification ; les pièces aussi (sensibilité `TLP:AMBER` par
  défaut). Un client qui exige un niveau minimal (par exemple `TLP:AMBER+STRICT`) n'avait aucune garantie qu'une
  erreur ne requalifie pas ses données à un niveau de partage plus large.
- **Décision** :
  1. **Politique du client** (nouvel écran du manager, « Politique des clients ») : un **TLP plancher** par client,
     réglé par un manager pour les clients dont il a la charge. Vide : pas de plancher, comportement d'avant.
  2. **Naissance au plancher** : les nouveaux tickets du client (ingestion d'une alerte) et ses nouvelles pièces sans
     sensibilité choisie naissent au plancher (à défaut, `TLP:AMBER`).
  3. **Monter, pas descendre** : un analyste peut monter un ticket (vers un niveau plus restrictif), jamais descendre
     sous le plancher ; un **manager** le peut, sur un ticket, avec un **motif** d'au moins 10 caractères, inscrit au
     registre des actions du ticket (événement `tlp_sous_plancher`, interne). Une pièce ne descend jamais sous le
     plancher. Contrôlé par le serveur (422), pas seulement grisé dans l'interface.
  4. **Changer le plancher** : le relever relève les tickets **ouverts** qui sont en dessous (événement `tlp_releve`
     par ticket) ; les tickets clos restent tels quels ; le baisser ne baisse aucun ticket. Chaque modification est
     inscrite au journal d'audit (`client.politique`, avec le nombre de tickets relevés).
  5. **Ordre** : marquage TLP 2.0 du FIRST, du moins au plus restrictif : CLEAR, GREEN, AMBER, AMBER+STRICT, RED.
- **Cloisonnement** : seul un manager règle la politique, et seulement pour ses clients (un autre client : 404) ;
  l'analyste, le client et l'Admin ne la règlent pas (403). Le client ne voit pas le plancher dans la fiche.
- **Conséquences** : migration `0022` (colonne `tlp_plancher` du client), routes `GET /api/v1/politique` et
  `PUT /api/v1/politique/{client}`. L'écran « Politique des clients » accueillera aussi les réglages d'astreinte du
  client (ADR-0032).
- **Tests** : `tests/test_politique.py`, `web/tests/tlp.test.mjs`, `e2e/scenarios/99-politique.mjs`, page vérifiée
  par axe-core (`90-accessibilite.mjs`).
