# ADR-0030 : Parc d'agents Wazuh

- **Statut** : accepté (24/11/2026).
- **Contexte** : un agent Wazuh arrêté ne produit plus d'alerte, et rien dans Keryx ne le montrait : un poste ou un
  serveur pouvait sortir de la surveillance sans que l'équipe le voie. Le mainteneur demande un tableau de bord des
  agents : état, version, depuis quand ils sont hors ligne.
- **Décision** :
  1. **Source** : l'API REST du manager Wazuh de chaque client, en lecture seule (`POST /security/user/authenticate`,
     `GET /` pour la version, `GET /agents` par pages). Keryx n'agit jamais sur Wazuh. Le dernier événement de
     chaque agent (tous niveaux, 30 derniers jours) vient de l'indexeur quand il est relié (ADR-0021), en une
     agrégation ; sans indexeur, la notion d'agent « silencieux » n'est pas proposée.
  2. **Connexion** : même connecteur que le contexte Wazuh (adresse résolue et contrôlée par Keryx, boucle locale,
     lien local et métadonnées refusés, TLS 1.2 au moins, autorité du client, aucune redirection, réponse bornée).
     Même autorité et même contrôle TLS que l'indexeur. Compte de lecture chiffré, jamais renvoyé ; changer
     l'adresse ou la confiance TLS l'efface.
  3. **Cloisonnement** (PDIS IV.3.8.g) : un manager qui sert plusieurs clients exige un groupe Wazuh par client,
     différent pour chacun ; Keryx demande ce groupe à l'API et **écarte lui-même** tout agent hors du groupe, même si
     le manager le renvoie. L'agent `000` (le manager) est ignoré.
  4. **Relevé** toutes les `KERYX_WAZUH_AGENTS_POLL_S` secondes (300 par défaut, 0 = à la demande seulement), et à la
     demande par l'équipe (deux fois par minute au plus et par client).
  5. **Historique** : une ligne par changement d'état constaté, **conservée sans limite** (décision du mainteneur).
     À la première observation, « depuis quand » vient du dernier contact (agent déconnecté) ou de l'enregistrement
     (jamais connecté). Disponibilité = temps actif sur le temps observé ; un agent jamais connecté ou en attente
     n'est pas compté (pas déployé n'est pas en panne).
  6. **Versions** : « en retard » si plus ancienne que le manager, « très ancienne » si autre version majeure ou trois
     versions mineures d'écart ou plus, « plus récente que le manager » signalée aussi. Ces seuils sont un choix du
     projet.
  7. **Pas de ticket automatique** (décision du mainteneur) : l'équipe ouvre à la main un ticket « agent
     déconnecté », qui passe par l'ingestion ordinaire (dédoublonnage, notifications, audit ; niveau 10).
  8. **Le client voit son parc** (décision du mainteneur), sans les éléments internes : ni nœud du manager, ni tickets,
     ni le détail technique d'un relevé en échec (seulement qu'il a échoué). L'Admin règle l'accès mais ne lit pas
     le parc.
  9. **Pilotage et rapport périodique** : état du parc et disponibilité moyenne sur la période, agents les moins
     disponibles.
- **Exigences** : PDIS IV.3.8.g (cloisonnement par client, au minimum logique), lue et citée dans
  `docs/deploiement-docker.md`. Le suivi de l'état des sondes de collecte relève aussi de la disponibilité du service
  de détection ; l'exigence PDIS précise n'a pas été relue pour cet ADR : **à vérifier**.
- **Conséquences** : une sortie réseau de Keryx vers chaque manager (port de l'API, souvent 55000) ; un compte
  d'API par client à créer côté Wazuh ; avec plusieurs processus Keryx, un seul doit avoir le relevé actif.
- **Non essayé** : contre un vrai manager Wazuh. Noms de champs, permissions du compte et forme des réponses ne sont
  vérifiés que contre le faux manager des tests (`tests/fake_wazuh_api.py`). À valider sur la préproduction.
- **Tests** : `tests/test_parc.py`, `e2e/scenarios/04-parc.mjs`, `e2e/scenarios/97-parc-ticket.mjs`.
