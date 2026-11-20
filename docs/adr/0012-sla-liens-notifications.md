# ADR-0012 — Échéances (SLA), liens entre tickets, notifications dans l'interface

- **Statut** : accepté (20/11/2026) ; **valeurs par défaut à valider avec chaque client**
- **Échéances** : deux délais par gravité, en heures, réglables par client. Par défaut — Critique 1 h / 8 h, Élevée 4 h / 24 h, Moyenne 24 h / 72 h, Faible 72 h / 168 h (qualification / résolution). Ces valeurs sont des hypothèses de travail, sans source normative. La qualification se mesure sur la criticité initiale (la gravité n'existe pas encore), la résolution sur la gravité qualifiée si elle existe. Les échéances sont internes : le client ne les voit pas.
- **Exigence** : PDIS IV.2.1.e, r, s (échelle définie avec le commanditaire). Aucune exigence ne fixe les délais : la cible est contractuelle.
- **Liens** : parent, lié, doublon, entre tickets d'un même client uniquement (le cloisonnement s'applique aux deux tickets). La fusion manuelle déplace alertes brutes et commentaires vers le ticket conservé et clôt l'autre en faux positif, avec motif tracé.
- **Notifications dans l'interface** : assignation, mention `@identifiant`, échéance dépassée (une seule fois par échéance), réponse du client. Référence et nature de l'événement seulement, jamais de détail de l'incident. Chaque utilisateur peut désactiver chaque type.
- **Recherche** : plein texte sur titre, règle, agent, IP et commentaires ; les commentaires internes ne sont jamais cherchés pour un client.
