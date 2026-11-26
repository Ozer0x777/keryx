# ADR-0031 : Indexeur Wazuh partagé entre clients, source Wazuh par client

- **Statut** : accepté (26/11/2026).
- **Contexte** : le contexte d'un ticket (ADR-0021) et le dernier événement des agents du parc (ADR-0030) cherchent
  dans l'indexeur Wazuh les événements d'un agent par son numéro (`agent.id`) et une période. Or ces numéros ne sont
  uniques que par manager : chaque manager numérote ses agents à partir de 001. Chez un MSSP, plusieurs managers
  (un par client) écrivent souvent dans le même indexeur. Keryx refusait déjà deux clients sur le même indexeur avec
  **exactement** le même motif d'index, mais pas des motifs différents qui se recouvrent (`wazuh-alerts-*` et
  `wazuh-alerts-4.x-*`) : l'analyste d'un client pouvait alors voir, dans la fiche d'un ticket, les événements de
  l'agent de même numéro d'un autre client. Relevé par une revue externe du code ; aucune fuite constatée.
- **Décision** :
  1. **Source Wazuh par client** (`wazuh_indexer_source`) : le nom de son manager (`manager.name`) ou de son cluster
     (`cluster.name`). Dans un cluster, `manager.name` désigne le nœud qui a traité l'alerte, d'où le choix de l'un
     ou de l'autre. Quand elle est réglée, chaque recherche dans l'indexeur la filtre (`manager.name` OU
     `cluster.name`), et Keryx **revérifie chaque événement reçu** : un événement d'une autre source est écarté et
     compté, même si l'indexeur l'a renvoyé.
  2. **Règle de partage** (PDIS IV.3.8.g) : deux clients sur le même indexeur (même hôte et même port) avec des
     motifs d'index qui **peuvent** se recouvrir doivent avoir chacun une source, différente (sans tenir compte de la
     casse). Le recouvrement est jugé prudemment : motifs égaux, ou parties fixes avant la première étoile qui se
     prolongent l'une l'autre. Sinon l'enregistrement est refusé (422).
  3. **Réglages antérieurs** : un client qui partage déjà son indexeur sans source voit le contexte refusé (409) et
     le parc ne lit plus le dernier événement de ses agents (la notion de « silencieux » est masquée) jusqu'à ce
     qu'un Admin règle les sources. Rien n'est jamais mêlé en attendant.
- **Exigences** : PDIS IV.3.8.g (cloisonnement des données des commanditaires) ; ASVS 5.0 V8 (contrôle d'accès
  aux données).
- **Conséquences** : un MSSP peut désormais faire lire le même indexeur et le même motif `wazuh-alerts-*` à
  plusieurs clients, à condition que leurs managers ou clusters portent des noms distincts. Deux clusters laissés à
  leur nom par défaut (`wazuh`) ne se distinguent pas : il faut renommer l'un d'eux ou séparer les motifs d'index.
  Migration `0021`.
- **Tests** : `tests/test_wazuh_context.py` (règle de partage et recouvrement des motifs, filtre par manager et par
  cluster, événements d'un autre manager écartés même quand l'indexeur les renvoie, réglage antérieur refusé),
  `tests/test_parc.py` (`test_silencieux_ne_lit_que_la_source_du_client`).
