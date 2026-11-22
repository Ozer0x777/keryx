# ADR-0013 : Mode crise

- **Statut** : accepté (20/11/2026)
- **Décision** : un ticket ouvert peut passer en mode crise (analyste ou manager) ; seul un manager clôt la crise. Le registre contient des décisions, des actions (cochables, avec responsable et échéance) et des points de synthèse, en texte brut (jamais interprété comme du HTML). Il est interne : le client n'y a pas accès. Chaque ouverture, clôture et entrée est inscrite au registre des actions et au journal d'audit.
- **Exigences** : PRIS VI.5.5.1 (registre de crise) ; PRIS VI.5.3.d.
- **Limite** : la gestion de crise du PRIS comprend aussi des aspects organisationnels (cellule de crise, communication) que l'outil ne couvre pas.
