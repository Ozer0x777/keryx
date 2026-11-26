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
  1. **Source Wazuh par client** (`wazuh_indexer_source`), typée : `manager:<nom>` (champ `manager.name`) ou
     `cluster:<nom>` (champ `cluster.name` ; dans un cluster, `manager.name` désigne le nœud qui a traité l'alerte).
     Quand elle est réglée, chaque recherche dans l'indexeur filtre sur ce seul champ, et Keryx **revérifie chaque
     événement reçu** : un événement d'une autre source est écarté et compté, même si l'indexeur l'a renvoyé.
  2. **Règle de partage** (PDIS IV.3.8.g) : deux clients dont les motifs d'index **peuvent** se recouvrir doivent
     avoir chacun une source, **du même type** et de noms différents (sans tenir compte de la casse). Les adresses des
     indexeurs ne sont pas comparées : un même serveur s'écrit de bien des façons (adresse IP sous plusieurs formes,
     alias DNS, IPv6), la règle vaut donc quel que soit l'indexeur. Deux types différents ne sont pas acceptés
     ensemble : un manager et un cluster peuvent porter le même nom. Le recouvrement des motifs est jugé prudemment :
     motifs égaux, ou parties fixes avant la première étoile qui se prolongent l'une l'autre.
  3. **Enregistrement et lecture** : un client peut enregistrer sa source même si un autre client concerné n'a pas
     encore la sienne (un Admin règle les clients un par un) ; un client sans source, ou dont la source entre en
     conflit avec une source déjà réglée, est refusé (422). La lecture, elle, est refusée (409 pour le contexte ;
     dernier événement du parc non lu) tant que tous les clients concernés n'ont pas une source distincte, et dès
     qu'un doute subsiste (client détaché de la session de base). Rien n'est jamais mêlé en attendant.
- **Exigences** : PDIS IV.3.8.g (cloisonnement des données des commanditaires) ; ASVS 5.0 V8 (contrôle d'accès
  aux données).
- **Conséquences** : un MSSP peut désormais faire lire le même indexeur et le même motif `wazuh-alerts-*` à
  plusieurs clients, à condition que leurs managers ou clusters portent des noms distincts. Deux clusters laissés à
  leur nom par défaut (`wazuh`) ne se distinguent pas : il faut renommer l'un d'eux ou séparer les motifs d'index.
  Migration `0021`.
- **Revue** : la règle a été durcie après une revue du code (26/11/2026) : adresses non comparées, type de source
  obligatoire, réglage client par client possible.
- **Tests** : `tests/test_wazuh_context.py` (règle de partage et recouvrement des motifs, indexeurs écrits autrement,
  types de source, filtre par manager et par cluster, événements d'un autre manager écartés même quand l'indexeur les
  renvoie, réglage antérieur refusé puis réparé client par client),
  `tests/test_parc.py` (`test_silencieux_ne_lit_que_la_source_du_client`).
