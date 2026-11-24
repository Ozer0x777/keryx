# Fiche analyste

## Première connexion

Votre administrateur vous remet un identifiant, un mot de passe temporaire et un code d'activation (valable 72 h).
À la première connexion, Keryx vous fait choisir votre mot de passe et enregistrer la double authentification dans
une application TOTP. Gardez les codes de secours affichés une seule fois. Si votre organisation utilise
l'authentification unique (SSO), utilisez le bouton correspondant.

## La file des tickets

- Chaque alerte Wazuh de niveau suffisant ouvre un ticket ; une alerte identique (même règle, même équipement) sur
  un ticket ouvert s'ajoute à ses occurrences au lieu d'en créer un autre.
- Les cartes du haut sont des filtres rapides. La seconde rangée, « À traiter en priorité », montre les critiques
  sans personne dessus, les tickets où le client n'a pas répondu, et les dossiers en réponse auxquels il manque la
  gravité, l'assigné ou la synthèse.
- « Mes tickets » et « Non assignés » filtrent par assigné. Les filtres restent dans l'adresse de la page : le
  bouton Précédent les retrouve, et « Enregistrer ce filtre » en fait un raccourci personnel.
- Le Kanban montre les mêmes tickets par phase ; glisser une carte (ou le menu « Déplacer… ») change son statut.

## Traiter un ticket

La fiche est en onglets ; la barre du haut garde la référence, les boutons d'étape et les saisies non enregistrées.

1. **Vue générale** : lire la description (l'alerte reçue), puis **qualifier** : verdict, dommages, importance de
   l'équipement, impact, risque, marquage TLP. Keryx propose une gravité ; « Retenir cette gravité » l'applique
   (c'est noté au registre comme venant de la proposition), sinon choisissez les dommages vous-même.
2. **Investigation** : contexte de l'alerte dans Wazuh si l'instance est reliée à l'indexeur, techniques MITRE
   ATT&CK, classification ETSI ISI.
3. **Preuves** : déposer une pièce (archive ZIP ou image, avec date et méthode de collecte), déclarer une preuve
   conservée hors de Keryx, consulter le registre des actions. Chaque téléchargement demande un motif.
4. **Communication** : un commentaire est **interne** par défaut. Cocher « Visible par le client » le rend lisible
   par le client ; Keryx demande alors confirmation en nommant le client, car il ne pourra plus être retiré.
   Mentionnez un collègue avec `@identifiant`.
5. **REX** : synthèse (chronologie, mode opératoire, périmètre) et retour d'expérience, obligatoire pour un
   incident de gravité Élevée ou Critique.

## Les étapes

Nouveau → En évaluation → En réponse → Clôturé → Retour d'expérience, ou En évaluation → Faux positif.

- « Faux positif » exige le verdict Faux positif et un **motif d'au moins 10 caractères**. Le motif reste interne :
  le client voit le changement de statut, jamais le motif.
- « En réponse », « Clôturé » et « Retour d'expérience » demandent confirmation : le client voit ces changements.
- Les échéances de qualification et de résolution sont dans l'en-tête de la fiche ; un ticket en retard est
  signalé dans la file.

## Le parc d'agents

« Parc Wazuh » montre les agents de chaque client : actifs, déconnectés (et depuis quand), jamais connectés, versions
en retard sur le manager, agents silencieux (actifs mais sans événement depuis 24 h, quand l'indexeur est relié).
Un agent hors ligne depuis plus de 24 h est en tête et signalé en rouge : ses alertes n'arrivent plus au SOC. Le
détail d'un agent montre sa disponibilité sur 7 et 30 jours et l'historique de ses changements d'état ; pour un agent
déconnecté, « Ouvrir un ticket agent déconnecté » crée le ticket (ou complète celui déjà ouvert).

## Bon à savoir

- Une pastille « Modifications non enregistrées » signale une saisie en cours ; quitter la page la demande de
  confirmer. Un commentaire en cours de rédaction est gardé en brouillon dans l'onglet du navigateur.
- « Horloge du manager Wazuh en avance » dans l'en-tête : la date de détection vient de Wazuh, celle de réception
  de Keryx ; prévenir l'exploitation (synchronisation NTP).
- Le mode crise ouvre un registre des décisions et un plan d'action ; seul un manager le clôt.
