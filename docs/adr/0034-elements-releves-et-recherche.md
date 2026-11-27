# ADR-0034 : éléments relevés dans les alertes, recherche par champ, liens entre tickets

- **Statut** : accepté (28/11/2026), décisions du mainteneur (revue de l'interface du 27/11/2026, propositions S14 à
  S17).
- **Contexte** : pour lier deux tickets, il fallait connaître la référence de l'autre ; la recherche de la file ne
  couvrait ni la description ni l'alerte brute, donc ni l'adresse source, ni le compte visé, ni une empreinte. Un même
  incident se répartit pourtant souvent sur plusieurs tickets (autre agent, autre règle) que seule une valeur commune
  relie. Le sens d'un lien « parent » n'était pas dit à l'écran.
- **Décision** :
  1. **Éléments relevés** : à la réception de chaque alerte, Keryx relève les adresses IP (partout, journal brut
     compris), les noms d'hôte, les comptes, les domaines (d'après le nom du champ) et les empreintes (seulement dans
     un champ dont le nom évoque un hash, pour ne pas prendre un identifiant hexadécimal quelconque). Table
     `observables` (client, ticket, type, valeur), valeurs normalisées et bornées (200 par alerte, 255 caractères),
     index sur (client, type, valeur). Le relevé est fait même quand l'alerte brute n'est plus conservée (plafond
     par ticket). La migration `0033` reprend les alertes brutes déjà conservées.
  2. **Cycle de vie** : les éléments suivent le ticket : fusion (rattachés au ticket conservé), rétention (purgés
     avec les alertes brutes), export complet du client (`elements-releves.json`), destruction.
  3. **Recherche** (`keryx/recherche.py`), file et fenêtre de lien : texte libre (référence, titre, règle, agent,
     description, commentaires ; alerte brute et commentaires internes pour l'équipe seulement) ou champ précis
     `ip:`, `hote:`, `agent:`, `regle:`, `compte:`, `hash:`, `domaine:`, `ref:`. Un champ précis cherche dans les
     éléments relevés (égalité sur la valeur normalisée, indexée).
  4. **Fenêtre de lien** : type expliqué (lié, parent / enfant, doublon), sens du lien parent choisi
     (`sens` : `enfant_de` ou `parent_de`), résultats qui disent où la valeur a été trouvée (titre, description,
     alerte brute avec le nom du champ, commentaire), conséquence écrite avant de valider ; pour un doublon, la
     fusion existante est proposée. Le lien est inscrit au registre des actions des deux tickets.
  5. **Suggestions** : sur la fiche, « Peut-être lié » liste les valeurs relevées que d'autres tickets du même client
     partagent (hors l'agent du ticket lui-même et les tickets déjà liés).
- **Cloisonnement** : la recherche, la fenêtre de lien et les suggestions ne portent que sur les clients de
  l'utilisateur, et la fenêtre de lien et les suggestions sur le seul client du ticket (un lien ne relie jamais deux
  clients). Le client n'interroge jamais l'alerte brute ni les commentaires internes ; la fenêtre de lien et les
  suggestions lui sont refusées (403). Chaque recherche de la fenêtre de lien est inscrite au journal d'audit
  (`ticket.link_search`, nombre de résultats, sans la valeur cherchée).
- **Conséquences** : migration `0033` ; routes `GET /api/v1/tickets/{ref}/links/search` et
  `GET /api/v1/tickets/{ref}/links/suggestions` ; paramètre `sens` de `POST /api/v1/tickets/{ref}/links`. La
  recherche en texte libre dans l'alerte brute est une recherche « contient » sans index : suffisante pour les
  volumes visés (petits SOC) ; un index plein texte (PostgreSQL) reste possible si le besoin apparaît.
- **Tests** : `tests/test_liens_recherche.py`, `e2e/scenarios/99-liens.mjs`.
