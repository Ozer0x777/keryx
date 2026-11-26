# ADR-0032 : Prévenir l'équipe, mesurer l'acquittement, vérifier la chaîne d'alerte de bout en bout

- **Statut** : proposé (26/11/2026). Rien n'est codé : ce document est à valider avant.
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
- **Questions ouvertes (à trancher avant de coder)** :
  1. Quelles criticités notifient l'astreinte : Critique seulement, ou aussi Élevée ?
  2. Délai avant escalade par défaut (proposition : 15 minutes pour Critique, 60 pour Élevée) et heures ouvrées ou
     non (proposition : en continu, l'astreinte étant justement là hors des heures ouvrées).
  3. Formats de webhook à fournir d'abord (proposition : JSON générique et Mattermost / Slack, qui couvre aussi
     beaucoup d'outils).
  4. Un canal par instance, ou par client (un MSSP peut avoir une équipe par client) ?
  5. Période du battement de cœur et délai d'alerte (proposition : ligne toutes les 5 minutes, alerte après 15).
  6. Le délai d'acquittement figure-t-il dans le rapport remis au client ?
- **Exigences** : PDIS (traitement et suivi des incidents, délais) : sections à citer après lecture du texte, non
  vérifiées à ce stade. ISO/IEC 27035 (détection et signalement).
- **Conséquences** : une table des canaux, des champs de suivi d'acquittement et d'escalade sur le ticket, une tâche
  de fond pour les escalades et la surveillance du battement (comme la relance des notifications), une règle et un
  exemple de tâche planifiée dans `integrations/wazuh/`, des tests avec un faux service de webhook.
