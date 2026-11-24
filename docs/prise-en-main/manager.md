# Fiche manager d'équipe

Le manager fait tout ce que fait l'analyste (voir [`analyste.md`](analyste.md)), et en plus :

## Piloter l'équipe

- **Pilotage** : tickets par statut et par gravité, charge par analyste, respect des échéances sur la période.
- **Parc d'agents** : le pilotage et le rapport périodique donnent l'état du parc et la disponibilité moyenne sur la
  période ; l'export CSV de la page « Parc Wazuh » sert aux revues avec le client.
- **Rapports** : rapport périodique d'un client (imprimable en PDF par le navigateur) et export du registre en CSV.
- Affecter un ou plusieurs tickets d'un coup : cocher les lignes de la file, puis « Affecter à ».
- Les cartes « Critiques non assignés » et « Dossiers incomplets » sont faites pour la revue quotidienne.

## Actions réservées au manager

- **Détruire une pièce** du registre des preuves (le contenu est effacé, la ligne, l'empreinte et la chaîne de
  possession restent).
- **Clore le mode crise** d'un ticket.
- Créer un **modèle de commentaire ou de synthèse commun** à tous les clients.
- **Table MITRE** : correspondances entre règles Wazuh et techniques ATT&CK, utilisées quand la règle n'en fournit
  pas ; Keryx propose d'y ajouter les techniques saisies à la main sur plusieurs tickets d'une même règle.
- **Journal d'audit** : consulter et exporter le journal scellé des actions.

## Points d'attention

- La gravité proposée par Keryx n'est qu'une proposition : vérifiez en revue que les analystes la confirment en
  connaissance de cause.
- Le motif d'un faux positif est interne : relisez-les régulièrement, ils montrent les règles Wazuh à affiner.
