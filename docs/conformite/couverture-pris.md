# Couverture du référentiel PRIS par Keryx

État au 27/11/2026. Sources lues en entier : le référentiel « Prestataires de réponse aux incidents de sécurité »
v3.2 du 7/10/2025, et la trame d'évaluation PRIS v1.4, faite pour la v3.0 du référentiel : sa numérotation est
décalée par endroits (la trame appelle VI.5.3.b le registre de collecte que la v3.2 numérote VI.5.3.c). Ce document
suit la numérotation de la v3.2. Les documents ne sont pas dans le dépôt ; leur texte fait foi.

## Ce que l'on évalue ici

Le référentiel couvre cinq activités : recherche d'indicateurs de compromission (REC), investigation numérique (INV),
analyse de codes malveillants (CODE), pilotage et coordination des investigations (PCI), gestion de crise d'origine
cyber (CRISE). Il porte en grande partie sur le prestataire et ses personnels (chapitres IV et V), la convention de
service et la note de cadrage, et sur des activités menées avec des outils d'analyse. Keryx intervient comme outil de
**pilotage et de suivi** (registres, synthèse, actions, crise, livrables), surtout pour les activités PCI et CRISE.

Statuts : **Couvert**, **Partiel**, **Écart** (Keryx devrait le fournir), **Hors Keryx** (personnel, contrat,
outils d'analyse, organisation).

## Exigences où Keryx intervient

| Exigence | Ce que l'évaluateur vérifie (résumé) | Statut | Preuve, ou manque |
|---|---|---|---|
| IV.1.d | Consentement avant toute communication à un tiers | Partiel | Recherche VirusTotal refusée sans l'accord du client enregistré par le manager ; le formulaire signé est un document du prestataire |
| IV.3.c | Protection en intégrité et confidentialité selon le marquage | Couvert | TLP (plancher par client), niveau de classification, empreintes SHA-256, chiffrement des secrets, journal chaîné |
| IV.3.d | Moindre privilège, besoin d'en connaître | Couvert | Rôles séparés, cloisonnement par client, rôle Admin sans accès aux tickets |
| IV.3.n, o | Revue périodique des droits d'accès | Couvert | Administration > Revue des comptes |
| IV.3.p | Conservation hors ligne de ce que le commanditaire autorise à garder | Partiel | Export complet d'un client (ZIP avec empreintes) à déposer sur le support hors ligne ; le système hors ligne lui-même : organisation |
| IV.3.q | Stockage et manipulation des codes malveillants | Couvert | Quarantaine dans une archive chiffrée, archives non analysables isolées, téléchargement confirmé et tracé |
| VI.3.b, c, d | [ELEVE, PCI] Posture initiale, dont le niveau de discrétion vis-à-vis de l'attaquant, validée et révisée | Couvert | Bloc « Posture » (démarche, jalons, activités, informations à collecter, effectifs, discrétion, validation) ; chaque révision au registre ; `test_pris.py` |
| VI.3.e, g | [CRISE] Impacts, enjeux ; critères et indicateurs de suivi et de sortie de crise | Couvert | Critères de sortie de crise au registre de crise, cochés quand ils sont atteints |
| VI.4.2 | Note de cadrage (marquage, conservation, registres…) | Hors Keryx | Document du prestataire ; peut être déposée comme pièce du ticket |
| VI.5.2.1.b | Respect du marquage des indicateurs (TLP, PAP) | Hors Keryx | Base d'indicateurs (par exemple MISP) |
| VI.5.2.4 | [ELEVE] Méthode de recherche en sources ouvertes selon le niveau de discrétion | Couvert | En discrétion élevée, recherche VirusTotal refusée depuis Keryx ; recherches journalisées ; la méthode elle-même : document du prestataire |
| VI.5.3.a | [ELEVE, PCI] Suivi régulier du commanditaire | Couvert | Point de situation imprimable (24 h, 3 ou 7 jours), commentaires visibles |
| VI.5.3.c | [ELEVE] Registre des informations et supports collectés : description, date et heure, méthode, sensibilité | Couvert | Registre des preuves (`Attachment`), chaîne de possession, horodatage qualifié, `test_attachments.py` |
| VI.5.3.d | [ELEVE, REC, INV, PCI] Registre des actions : date et heure, description, objet (information, support ou ressource du SI cible) | Partiel | Chaîne de possession des pièces et registre du ticket ; pas d'inscription structurée d'une action sur une ressource du SI cible |
| VI.5.3.e | [INV, PCI] Synthèse de la compréhension : attaquant présent, compromission initiale, chronologie, mode opératoire en huit volets, caractérisation de l'attaquant, périmètre | Couvert | Bloc « Compréhension de l'incident » (présence, huit volets du mode opératoire, potentiel, niveau de menace, objectifs, vecteur, privilèges, ressources et comptes compromis) avec la synthèse existante (compromission initiale, chronologie) |
| VI.5.4.a, b | [INV, PCI] Mesures d'endiguement proposées et réévaluées ; procédures d'urgence « bouton rouge » | Couvert | Mesures proposées par l'équipe, acceptées ou refusées par le commanditaire (portail, ou décision rapportée avec son auteur), appliquées puis levées ; procédures d'urgence distinguées ; `99-pris.mjs` |
| VI.5.5.1.d | [CRISE] Ressources humaines, logistique, [ELEVE] dérogations et risques | Partiel | Dérogations et risque associé au registre de crise ; ressources humaines et logistique : conseil du prestataire |
| VI.5.5.1.e, f, g | [CRISE] Plan d'action : objectifs stratégiques déclinés en objectifs opérationnels avec délai, validé, évalué | Couvert | Objectifs stratégiques, actions rattachées avec responsable et délai, validation par la cellule de crise stratégique, état coché |
| VI.5.5.1.h | [CRISE] Synthèse de la situation de crise ; conditions de sortie évaluées | Couvert | Synthèses de crise et critères de sortie |
| VI.5.5.1.j | [CRISE] Registre des actions de crise : date, description, arbitrage et entité responsable | Couvert | Une action référence l'arbitrage qui l'a permise ; une décision porte l'entité responsable |
| VI.6.a | [ELEVE] Restitution « à chaud » chaque jour | Couvert | Point de situation : activité de la période, compréhension, posture, mesures, crise |
| VI.6.c, e | [ELEVE, CRISE] Retour d'expérience et ses rubriques | Partiel | Retour d'expérience obligatoire pour les incidents graves, en texte libre |
| VI.7 | Rapport : qualification, cadre, synthèse managériale, résultats, annexes | Couvert | Rapport d'analyse imprimable en cinq parties (VI.7.1 à VI.7.5) : cadre saisi dans « Cadre du rapport d'analyse », reste repris du ticket ; champ non renseigné signalé |
| VI.7.5.b, c, d | [ELEVE] Annexes : registres des informations collectées et des actions, plan et registre de crise | Couvert | Annexes du rapport d'analyse : registre des informations et supports collectés, registre des actions, plan d'action et registre de crise, critères de sortie, retour d'expérience ; note de cadrage : pièce du ticket |
| VI.8.b, c | Restitution, effacement ou destruction ; conservation hors ligne | Couvert | Export complet puis `keryx destroy-client` |
| VI.8.d | [ELEVE] Recommandé : procès-verbal de destruction | Couvert | `keryx destroy-client --pv` : tickets et pièces (empreintes) identifiés, date et mode de destruction |

## Hors du logiciel

Chapitre IV (sauf c, d, n, o, p, q) : personne morale, droit applicable, impartialité, plaintes, gestion des
personnels, homologation. Chapitre V : compétences, expérience, contrats. VI.1, VI.2 : qualification préalable
d'aptitude, convention de service. VI.4 : équipe, note de cadrage, précautions, réunion d'ouverture. VI.5.1, VI.5.2
(sauf 2.4) : collecte et analyse, faites avec des outils d'investigation. VI.5.5.2 : communication de crise (conseil).
VI.8.a : réunion de clôture. Annexes 2 à 4.

## Écarts du logiciel

Corrigés le 27/11/2026 : synthèse structurée (VI.5.3.e), posture et discrétion avec refus des recherches en source
ouverte en discrétion élevée (VI.3.b, VI.5.2.4), mesures d'endiguement décidées par le commanditaire (VI.5.4),
registre de crise complété (VI.3.g, VI.5.5.1), rapport d'analyse (VI.7), point de situation (VI.6.a),
procès-verbal de destruction (VI.8.d).

Restent partiels, faute d'objet logiciel précis : le registre des actions réalisées sur une ressource du SI cible
(VI.5.3.d, à consigner aujourd'hui dans le registre du ticket), et le retour d'expérience structuré par rubriques
(VI.6.e, texte libre).
