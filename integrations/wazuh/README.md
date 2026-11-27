# Brancher Wazuh sur Keryx

Testé uniquement avec des alertes simulées : à valider sur ton manager Wazuh.

## 1. Créer la clé d'ingestion côté Keryx

```bash
python -m keryx.cli add-api-key ACME wazuh-manager-01
```

La clé n'est affichée qu'une fois. Une clé = un manager Wazuh = un client. Elle se crée aussi dans l'interface
(Administration > Clés d'API). Avec le déploiement Docker (`deploy/docker`) :
`docker compose exec keryx python -m keryx.cli add-api-key ACME wazuh-manager-01` ; `install.sh` affiche en fin
d'installation le bloc `<integration>` avec l'adresse réelle.

## 2. Installer le script sur le manager Wazuh

Wazuh exige que les intégrations personnalisées soient nommées `custom-…` et placées dans
`/var/ossec/integrations/`. Le wrapper `custom-keryx` (sans extension) lance le script Python
avec l'interpréteur embarqué de Wazuh.

```bash
sudo cp custom-keryx.py /var/ossec/integrations/custom-keryx.py
sudo cp custom-keryx /var/ossec/integrations/custom-keryx
sudo chmod 750 /var/ossec/integrations/custom-keryx /var/ossec/integrations/custom-keryx.py
sudo chown root:wazuh /var/ossec/integrations/custom-keryx /var/ossec/integrations/custom-keryx.py
```

## 3. Déclarer l'intégration dans `/var/ossec/etc/ossec.conf`

```xml
<integration>
  <name>custom-keryx</name>
  <hook_url>https://keryx.example.eu/api/v1/ingest/wazuh</hook_url>
  <api_key>kx_REMPLACER_PAR_LA_CLE</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Dans un **cluster Wazuh**, ce bloc `<integration>`, le script et son wrapper vont sur **chaque nœud qui analyse des
agents** (chaque nœud où les alertes sont produites), pas seulement sur le maître : un nœud sans le bloc n'envoie rien à
Keryx. La configuration de `ossec.conf` n'est pas synchronisée entre nœuds par le cluster.

`<level>7</level>` : seules les alertes de niveau 7 ou plus quittent le manager (même seuil que Keryx).

Si le certificat de Keryx est signé par une autorité privée (mode `local` ou `fourni` du déploiement Docker), le script
doit la connaître : variable d'environnement `KERYX_CA_BUNDLE` (chemin du certificat de l'autorité, PEM) dans
l'environnement du service `wazuh-manager`.

Puis : `sudo systemctl restart wazuh-manager`. Les traces de l'intégration sont dans
`/var/ossec/logs/integrations.log`.

### Limites observées côté Wazuh (préproduction, Wazuh 4.14.10, 27/11/2026)

Constats tirés des données d'un essai de quatre jours (24 568 alertes de niveau 7 ou plus), **non lus dans le code de
Wazuh** : à vérifier pour votre version.

- **Alertes de plus de 64 Kio jamais transmises.** Les 22 alertes de plus de 65 536 octets de la période n'ont été
  envoyées à aucune intégration, sans aucune trace dans les journaux du manager ; toutes les autres sont arrivées.
  Une alerte volumineuse (script PowerShell long, évènement chargé) peut donc ne jamais atteindre Keryx. À surveiller
  sur le manager, par exemple chaque jour :

  ```bash
  LC_ALL=C awk 'length($0) > 65536' /var/ossec/logs/alerts/alerts.json \
    | jq -c 'select(.rule.level >= 7) | {id, regle: .rule.id, agent: .agent.name}'
  ```

  Et réduire la taille de ces alertes à la source (champs repris en double dans le décodeur ou la règle).
- **Débit : une alerte à la fois.** Le manager lance le script une fois par alerte (environ 0,26 s chacune, soit
  quelque 14 000 alertes par heure au plus, Keryx en traitant une en 0,025 s). Une rafale plus rapide (campagne de
  tests, attaque bruyante) est mise en file puis livrée dans l'ordre, sans perte : 30 minutes de retard ont été
  mesurées après une rafale de 9 640 alertes en 3 minutes. Pour les règles très bavardes, regrouper côté Wazuh ou
  relever leur niveau ; une seconde intégration sur les mêmes alertes ralentit aussi la file.
- **Horloge.** Le délai entre la production d'une alerte et sa réception se lit avec les heures du manager : mettre
  le manager à l'heure (NTP), sinon les délais affichés sont faussés.

## 4. (Optionnel) Importance des équipements

Pour pré-remplir l'importance (standard / sensible / vital) utilisée dans la gravité,
ajouter un label dans l'`ossec.conf` de l'agent concerné :

```xml
<labels>
  <label key="importance">vital</label>
</labels>
```

Keryx lit `agent.labels.importance` dans l'alerte. À vérifier sur ton instance que le label
apparaît bien à cet emplacement dans le JSON des alertes.

## 5. (Optionnel) Journal d'audit de Keryx dans Wazuh

Définir `KERYX_SYSLOG_HOST` et `KERYX_SYSLOG_PORT` sur le serveur Keryx : chaque entrée du
journal d'audit est envoyée en syslog RFC 5424, ce qui permet au SOC de superviser son propre outil.

## 6. (Optionnel) Parc d'agents : compte de lecture de l'API du manager

Le tableau de bord « Parc Wazuh » de Keryx lit l'état des agents dans l'API REST du manager (port 55000 par défaut),
en lecture seule (ADR-0030). Créer côté Wazuh un utilisateur d'API dédié, limité à la lecture des agents du client :
une politique RBAC avec l'action `agent:read` sur la ressource `agent:group:<groupe du client>` (ou `agent:id:*` si
le manager ne sert qu'un client), rattachée à un rôle donné à cet utilisateur. Les noms exacts des actions et des
ressources dépendent de la version de Wazuh : **à vérifier dans sa documentation RBAC** avant de créer le compte.
Essayé le 27/11/2026 contre un manager Wazuh 4.14.10 avec un utilisateur portant le rôle prédéfini
`agents_readonly` (lecture des agents et des groupes) : relevé complet des agents.

Puis, dans Keryx (Admin, Administration > Clients > Paramétrer > Parc d'agents Wazuh) : adresse de l'API, groupe
Wazuh des agents du client (obligatoire si le manager sert plusieurs clients), identifiant et mot de passe. La même
autorité de certification que pour l'indexeur est utilisée. Keryx doit pouvoir joindre le manager (sortie réseau).

## 7. (Optionnel) Battement de cœur de la chaîne d'alerte

Une ligne de test part régulièrement du manager et traverse toute la chaîne (collecte, analyse, règle, intégration,
réseau) jusqu'à Keryx. Keryx la reconnaît, ne crée aucun ticket, note l'heure de réception et signale son absence :
bandeau de l'équipe, état du système de l'Admin, et canal d'astreinte du client s'il en a un. Sans battement, un
silence ne dit pas si la chaîne est coupée ou si tout est calme. Non essayé sur un manager Wazuh réel : à valider.

Sur **chaque manager (chaque nœud qui analyse)** du client :

1. la tâche planifiée : `sudo cp keryx-battement.cron /etc/cron.d/keryx-battement` (une ligne toutes les 5 minutes
   dans `/var/ossec/logs/keryx-battement.log`) ;
2. la règle : `sudo cp keryx-battement.xml /var/ossec/etc/rules/keryx-battement.xml` puis
   `sudo chown wazuh:wazuh /var/ossec/etc/rules/keryx-battement.xml` (règle 119990, niveau 3, groupe
   `keryx_battement` ; changer l'identifiant s'il est déjà pris) ;
3. dans `/var/ossec/etc/ossec.conf`, la lecture du journal et un second bloc d'intégration, filtré sur le groupe (le
   premier, filtré sur le niveau 7, ne l'enverrait pas) :

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/keryx-battement.log</location>
</localfile>

<integration>
  <name>custom-keryx</name>
  <hook_url>https://keryx.example.eu/api/v1/ingest/wazuh</hook_url>
  <api_key>kx_MEME_CLE_QUE_LE_PREMIER_BLOC</api_key>
  <group>keryx_battement</group>
  <alert_format>json</alert_format>
</integration>
```

4. `sudo systemctl restart wazuh-manager`, puis vérifier la règle : `sudo /var/ossec/bin/wazuh-logtest` et coller une
   ligne du journal (attendu : règle 119990, groupe `keryx_battement`).

Dans Keryx, le manager active le battement du client dans **Politique des clients**, avec la période de la tâche
planifiée (5 minutes) et le délai d'alerte (15 minutes par défaut, au moins deux périodes). Le délai court dès
l'activation : un client activé mais jamais branché est signalé. Le retour des battements est signalé aussi.

## Rétention des alertes côté Wazuh : 12 mois (à relever)

Le plan de projet fixe 12 mois pour les index `wazuh-alerts-*` (PDIS IV.2.2.w : 6 mois minimum ; PDIS IV.2.1.ee : analyse rétroactive sur 6 mois à la demande). Les exemples de la documentation Wazuh sont à 90 jours : à relever. Exemple de politique ISM (Wazuh indexer, onglet Dev Tools) :

```json
PUT _plugins/_ism/policies/wazuh-alerts-12-mois
{
  "policy": {
    "description": "Conserver les alertes Wazuh 12 mois puis les supprimer",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [], "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "365d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ["wazuh-alerts-*"], "priority": 100 } ]
  }
}
```

Cette politique n'a pas été exécutée sur un indexer depuis Keryx : la tester sur un environnement de recette, et valider la durée avec le DPO. Côté Keryx, la rétention des alertes brutes se règle par client (Administration > Clients) et par `KERYX_RETENTION_MONTHS`.
