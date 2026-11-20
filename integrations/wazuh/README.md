# Brancher Wazuh sur Keryx

Testé uniquement avec des alertes simulées : à valider sur ton manager Wazuh.

## 1. Créer la clé d'ingestion côté Keryx

```bash
python -m keryx.cli add-api-key ACME wazuh-manager-01
```

La clé n'est affichée qu'une fois. Une clé = un manager Wazuh = un client.

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

`<level>7</level>` : seules les alertes de niveau 7 ou plus quittent le manager (même seuil que Keryx).

Puis : `sudo systemctl restart wazuh-manager`. Les traces de l'intégration sont dans
`/var/ossec/logs/integrations.log`.

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
