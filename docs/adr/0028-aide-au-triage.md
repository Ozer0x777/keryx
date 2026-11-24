# ADR-0028 : Aide au triage : titres courts, écart d'horloge, gravité proposée

- **Statut** : accepté (24/11/2026). Partie de la vague « aide au triage » qui ne dépend d'aucune décision du
  mainteneur ; la table MITRE des règles du laboratoire, la grille de criticité et les tickets de test restent à
  décider.
- **Contexte** : le premier essai contre un vrai manager Wazuh (préproduction, 188 alertes) a montré trois freins au
  triage : des titres faits d'une ligne de commande entière (règles PowerShell et pare-feu Windows), une date de
  détection décalée de quelques minutes par rapport à Keryx sans que rien ne le signale, et une gravité vide sur
  chaque ticket tant que l'analyste ne l'a pas qualifiée à la main.
- **Décision** :
  1. **Titre court** : la description de la règle, espaces normalisés, coupée à 100 caractères sur une limite de
     mot, suivie de « … » et du nom de l'agent. Rien n'est réécrit ni deviné : c'est le début exact de la
     description, dont le texte complet reste dans le corps du ticket et dans les données de la règle.
  2. **Écart d'horloge** : la fiche montre la date de détection (horloge du manager Wazuh) et la date de réception
     (horloge de Keryx). Réception antérieure de plus d'une minute à la détection : pastille « horloge du manager en
     avance ». Réception plus de 15 minutes après la détection : pastille « reçu N min après ». Équipe seulement.
  3. **Gravité proposée** : tant que les dommages ne sont pas qualifiés, Keryx propose les dommages dont la gravité,
     selon la grille du client et l'importance de l'équipement, est la plus proche de la criticité initiale (niveau
     de la règle Wazuh) ; à égalité, les dommages les plus faibles. **Rien n'est appliqué sans un clic** de
     l'analyste (« Retenir cette gravité »), et le registre des actions comme l'audit notent `source : proposition`.
     La grille et le calcul de la gravité ne changent pas.
- **Exigences** : PDIS IV.2.1.q (qualification consignée) ; le choix de la proposition est une règle du projet,
  pas une exigence citée.
- **Conséquences** : la proposition hérite des limites de la criticité initiale : une règle de niveau 7 à 9 reste
  proposée « Faible » sur un équipement standard. C'est la question de la grille, laissée au mainteneur.
- **Tests** : `tests/test_aide_triage.py`, `e2e/scenarios/24-aide-triage.mjs`.
