# ADR-0003 — Importance de l'équipement lue dans les labels d'agent Wazuh

- **Statut** : accepté (20/11/2026) — **modifie une décision antérieure**
- **Contexte** : le plan prévoyait de déduire l'importance (standard / sensible / vital) du *groupe* d'agents Wazuh. Le groupe d'un agent n'est pas fourni dans le JSON des alertes.
- **Décision** : utiliser un label d'agent `importance` (section `<labels>` de l'`ossec.conf` de l'agent). La documentation Wazuh indique que les labels sont ajoutés aux alertes. Keryx lit `agent.labels.importance`, valeur par défaut `standard`.
- **À vérifier** : l'emplacement exact du label dans le JSON des alertes sur l'instance Wazuh cible.
- **Exigences** : PDIS IV.2.1.e, r, s (gravité définie avec le client) ; ISO/IEC 27035 (gravité selon l'importance des actifs).
