# ADR-0032 : Prévenir l'équipe, mesurer l'acquittement, vérifier la chaîne d'alerte de bout en bout

- **Statut** : accepté (26/11/2026). Questions tranchées par le mainteneur le 26/11/2026 (voir « Réglages »).
  Parties 1 (délai d'acquittement, « Je prends », choix du rapport client) et 2 (canaux, astreinte, escalade)
  codées le 26/11/2026 ; partie 3 (battement de cœur) à coder.
- **Contexte** : le pire scénario pour un SOC est une alerte critique que personne ne traite parce que personne n'a
  été prévenu, ou une chaîne d'alerte tombée en silence sans que personne ne s'en aperçoive. Aujourd'hui :
  - Keryx garde l'identifiant Wazuh, l'horodatage de détection et l'alerte brute de chaque ticket ;
  - il envoie un courriel aux **contacts du client** à l'ouverture d'un ticket (statut, nombre de tentatives,
    relances), mais **rien à l'équipe** : elle découvre un ticket critique en ouvrant l'interface ;
  - il n'a qu'un canal, le courriel, et aucune escalade ;
  - il mesure le délai de qualification, pas le délai avant la première action humaine ;
  - il repère une clé d'API muette (aucune alerte depuis un délai) et un agent silencieux, mais ne vérifie pas que la
    chaîne Wazuh vers Keryx fonctionne de bout en bout.
- **Décision proposée** :
  1. **Délai d'acquittement.** Pour chaque ticket, Keryx retient la première action humaine : prise en charge
     (nouveau bouton « Je prends » : s'affecter le ticket, événement `prise_en_charge`), affectation, changement de
     statut ou qualification. Le délai d'acquittement va de la détection Wazuh (`detected_at`) à cette action. Il
     s'affiche dans la fiche, le pilotage (moyenne et 90e centile par criticité, sur la période) et le rapport
     périodique du client. Aucune donnée nouvelle n'est demandée à Wazuh. Une consultation seule n'acquitte pas.
  2. **Notification de l'équipe et escalade.** Canaux d'astreinte réglés par un Admin : **webhook** (format JSON
     générique, ou compatible Mattermost / Slack / Teams, ou ntfy), courriel de l'équipe. Une ouverture de ticket de
     criticité Critique (et Élevée si le réglage le prévoit) notifie le canal d'astreinte ; sans action humaine au bout
     de N minutes (réglage par criticité), Keryx notifie le canal d'**escalade**, puis s'arrête (pas de répétition
     sans fin). Chaque envoi est enregistré comme les notifications actuelles (canal, destinataire, statut, tentatives)
     avec le code de réponse du service : c'est le seul « statut de livraison » fiable, Keryx ne prétend pas savoir si
     le message a été lu. La livraison elle-même (SMS, appel, rotation d'astreinte) reste l'affaire d'un outil dédié,
     joint par webhook : Keryx ne refait pas un outil d'astreinte.
  3. **Battement de cœur de bout en bout.** Une ligne de journal émise régulièrement sur chaque manager Wazuh (tâche
     planifiée qui écrit par exemple `keryx-battement <client>`), une règle Wazuh fournie qui la reconnaît (groupe
     `keryx_battement`, niveau suffisant pour déclencher l'intégration) : la ligne traverse toute la chaîne (collecte,
     analyse, règle, intégration, réseau, Keryx). Keryx la reconnaît à son groupe, ne crée aucun ticket, note l'heure
     de réception par client et signale l'absence au-delà d'un délai (état du système, bandeau de l'équipe, canal
     d'astreinte). Cela complète les « sources muettes », qui ne disent pas si le silence vient d'une panne ou d'une
     période calme.
  4. **Ce qui n'est pas fait** : suivi de lecture chez les fournisseurs, identifiants de transaction propres à chaque
     service, rotation d'astreinte, appels téléphoniques. Ils relèvent d'un outil d'astreinte.
- **Sécurité et confidentialité** :
  - tout est **désactivé par défaut** (aucun service externe appelé par défaut) ;
  - même connecteur sortant que les autres : HTTPS seulement, certificat vérifié, aucune redirection suivie, adresses
    de boucle locale, de lien local et de métadonnées refusées, délais bornés, secret du webhook chiffré au repos ;
  - **minimisation** : par défaut, le message ne contient que la référence, le client, la criticité et le lien vers
    Keryx (pas le titre ni l'agent, qui peuvent être sensibles et partiraient chez un tiers) ; un réglage permet
    d'ajouter le titre ;
  - le client ne voit ni les canaux d'astreinte ni les escalades ; l'Admin règle les canaux sans lire les tickets ;
  - chaque envoi, escalade et battement manqué est inscrit au journal d'audit.
- **Réglages (décisions du mainteneur, 26/11/2026)** :
  1. **Par client** (cas du MSSP : une équipe ou une astreinte par client). Le **manager** règle, pour chaque client
     dont il a la charge : l'activation de l'astreinte, les **criticités** qui la préviennent (Critique, Élevée,
     Moyenne, Faible), les **délais d'escalade** par criticité, et la période et le délai d'alerte du **battement de
     cœur**. Valeurs proposées à la création : Critique seulement, escalade à 15 minutes, battement toutes les
     5 minutes et alerte après 15, en continu.
  2. **Canaux** : l'**Admin** déclare les canaux (adresse du webhook, format, secret chiffré, ou adresse courriel de
     l'équipe), parce qu'une adresse appelée par le serveur est un réglage de sécurité, comme les connecteurs Wazuh et
     VirusTotal ; le manager choisit, pour chaque client, le canal d'astreinte et le canal d'escalade parmi eux.
  3. **Formats** d'abord : JSON générique et Mattermost / Slack (couvre aussi beaucoup d'autres outils).
  4. **Rapport au client** : le manager active ou désactive, client par client, l'envoi du délai d'acquittement dans
     le rapport périodique remis au client (désactivé par défaut). Il reste toujours visible de l'équipe.
  5. Chaque modification de ces réglages est inscrite au journal d'audit, avec son auteur.
- **Exigences** : PDIS (traitement et suivi des incidents, délais) : sections à citer après lecture du texte, non
  vérifiées à ce stade. ISO/IEC 27035 (détection et signalement).
- **Partie 1, telle que codée** : champs `acquitted_at` et `acquitted_by` du ticket (migration `0023`), posés par
  la première action de l'équipe parmi `prise_en_charge`, `affectation`, `statut`, `qualification` (un client, un
  commentaire, une pièce ou une consultation n'acquittent pas) ; route `POST /api/v1/tickets/{ref}/prise-en-charge` ;
  délai d'acquittement par criticité initiale (moyenne et 90e centile, en minutes, tickets créés sur la période) dans
  le pilotage, et dans le rapport périodique seulement si le manager a coché ce choix dans « Politique des clients »
  (`acquittement_rapport`, désactivé par défaut, inscrit au journal d'audit). Tests : `tests/test_acquittement.py`,
  `e2e/scenarios/99-acquittement.mjs`.
- **Partie 2, telle que codée** :
  - table `canaux_astreinte` (migration `0024`) : l'Admin déclare un canal (webhook JSON générique, webhook
    Mattermost / Slack, webhook Microsoft Teams par l'application Workflows avec une carte adaptative, les
    connecteurs Office 365 étant retirés par Microsoft, ou courriel de l'équipe) dans Administration > Canaux d'astreinte. L'adresse, qui contient
    souvent le jeton du webhook, et le secret de signature sont chiffrés au repos (AES-256-GCM, contexte propre au
    canal) et ne sont jamais renvoyés : seul l'hôte est affiché. Bouton « Envoyer un essai » sans donnée de ticket ;
  - le manager règle, par client, dans « Politique des clients » : activation, canal d'astreinte, canal d'escalade
    (facultatif), criticités qui préviennent (Critique par défaut) et délai d'escalade par criticité (1 à 1440 min ;
    15, 30, 60, 120 par défaut). Il voit le nom des canaux actifs, jamais leur adresse ;
  - à l'ingestion, un ticket d'une criticité choisie prévient le canal d'astreinte (`astreinte_at`, événement interne
    `astreinte`) ; une tâche de fond (`KERYX_ASTREINTE_TICK_S`, 60 s) escalade une fois, par prise atomique, les
    tickets ouverts non acquittés au-delà du délai (`escalade_at`, événement interne `escalade`, auteur `keryx`) ;
  - chaque envoi est inscrit au registre des notifications (canal, motif, statut, tentatives, code de réponse) et au
    journal d'audit ; les envois en échec sont relancés avec un délai croissant, 5 tentatives au plus ;
  - webhook JSON générique signé si un secret est réglé : `X-Keryx-Timestamp` et
    `X-Keryx-Signature: sha256=HMAC(secret, horodatage.corps)` ;
  - règle de sortie du connecteur Wazuh : HTTPS, certificat vérifié (`KERYX_ASTREINTE_CA_FILE` pour une autorité
    interne), pas d'identifiants dans l'URL, aucune redirection suivie, nom résolu et chaque adresse contrôlée avant
    la connexion, réponse bornée ;
  - tests : `tests/test_astreinte.py` (faux service de webhook HTTPS), `e2e/scenarios/99-astreinte.mjs`.
- **Conséquences** : une table des canaux, des champs de suivi d'acquittement et d'escalade sur le ticket, une tâche
  de fond pour les escalades et la surveillance du battement (comme la relance des notifications), une règle et un
  exemple de tâche planifiée dans `integrations/wazuh/`, des tests avec un faux service de webhook.
