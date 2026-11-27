# Couverture du référentiel PDIS par Keryx

État au 26/11/2026, version 0.9.0. Sources lues en entier : le référentiel « Prestataires de détection des incidents
de sécurité » v2.0 du 21/12/2017, et la trame d'évaluation PDIS v1.1 du 17/03/2025, qui intègre l'addendum
n°42/ANSSI/SDE/NP (options A et B). Ces documents ne sont pas dans le dépôt ; le texte du référentiel fait foi, les
résumés ci-dessous ne le remplacent pas.

## Ce que l'on évalue ici

La qualification porte sur un **prestataire** : son organisation, son personnel, ses locaux, son infrastructure, ses
contrats, et les outils qu'il exploite. Keryx n'est qu'un de ces outils : l'outil de gestion des tickets d'incident
(zone d'analyse), l'émission des notifications (par un relais de la zone de notification) et, en mode tout-en-un, le
portail des clients. La collecte, le stockage et l'indexation des évènements, et les règles de détection, sont dans
Wazuh. Le reste relève de l'infrastructure et de l'organisation du prestataire.

Statuts :

- **Couvert** : Keryx fournit ce que l'évaluateur vérifiera, preuve indiquée ;
- **Partiel** : Keryx fournit une partie ; le manque est décrit ;
- **Écart** : Keryx devrait le fournir et ne le fait pas : correction listée en fin de document ;
- **Wazuh**, **Infrastructure**, **Organisation** : hors du logiciel Keryx, à la charge du prestataire.

## Exigences où Keryx intervient

| Exigence | Ce que l'évaluateur vérifie (résumé) | Statut | Preuve, ou manque |
|---|---|---|---|
| IV.1.g | Consentement du client avant toute communication d'informations | Couvert | Recherche VirusTotal refusée tant que le manager n'a pas enregistré l'accord du client (« Politique des clients »), `test_virustotal.py` |
| IV.2.1.b, c | Catégories d'incidents redoutés ; recommandé : ETSI GS ISI | Partiel | Classification ETSI GS ISI sur le ticket (`routes_isi.py`) ; la liste des incidents redoutés est un document du prestataire |
| IV.2.1.g à p | Règles de détection : marquage, liste versionnée, bulletin mensuel, registre des ajouts | Wazuh | Les règles vivent dans Wazuh ; Keryx ne tient ni liste versionnée ni bulletin d'état des règles |
| IV.2.1.q, r | Qualification (véracité, gravité) selon une échelle établie avec le client | Couvert | Verdict, dommages et importance, grille de gravité par client (`severity.py`), gravité proposée (ADR-0028) |
| IV.2.1.s | Recommandé : échelle de gravité de l'annexe C d'ISO/IEC 27035 | Partiel | Échelle à quatre niveaux propre à Keryx, réglable par client ; non alignée mot pour mot sur l'annexe C |
| IV.2.1.t, u | Recherche en sources ouvertes : méthode, marquage, prudence | Partiel | Recherches VirusTotal tracées au journal d'audit ; le marquage des règles n'est pas consulté ; la requête part du serveur (voir IV.3.10.a) |
| IV.2.1.w | Contenu minimal du ticket | Couvert | Création et registre des actions, date de détection, description, niveau de classification (Non protégé, Diffusion Restreinte), gravité, impact, risque induit, identifiant et version de la règle (celle de l'alerte, sinon le jeu de règles déclaré), équipement source, collecteur, identifiants des évènements ; `test_contenu_ticket.py` |
| IV.2.1.x, y | Format des tickets défini avec le client ; recommandé : ETSI GS ISI | Partiel | Export IODEF (RFC 7970) ; classification ETSI GS ISI ; format à fixer dans la convention |
| IV.2.1.z | Outil de gestion des tickets dans la zone d'analyse | Couvert | Keryx |
| IV.2.1.aa | Contexte stocké avec le ticket, quel que soit son état | Couvert | Alertes brutes avec empreinte, pièces, synthèse, retour d'expérience ; conservés toute la prestation par défaut (IV.5.3.6) |
| IV.2.1.bb | Registre centralisé et chronologique par client | Couvert | `GET /api/v1/registre` (CSV), `test_reports.py` |
| IV.2.1.cc | Capacité de stockage des tickets suivie | Couvert | Taille de la base et remplissage du disque des pièces dans le pilotage ; stockage objet : suivi par son outil |
| IV.2.1.dd, ee | Analyse a posteriori, recherche d'indicateurs sur 6 mois | Wazuh | Indexeur Wazuh ; Keryx lit le contexte d'un agent (ADR-0021), il ne cherche pas dans tout l'historique |
| IV.2.2 (sauf r, s) | Stratégie et capacité de collecte, collecteurs, indexation | Wazuh | |
| IV.2.2.r | Le collecteur détecte une perte de communication | Partiel | Battement de cœur de la chaîne (ADR-0032) : complément de bout en bout, la détection au collecteur reste à Wazuh |
| IV.2.2.s | Chaque évènement associé à son collecteur | Wazuh | Keryx conserve `manager.name` dans l'alerte brute |
| IV.2.3.a, b | Canal de notification et canal sécurisé ; deux moyens de notification, le secondaire testé tous les six mois | Couvert | Courriel aux contacts ; moyen secondaire (canal déclaré par l'Admin, par exemple un service de SMS) quand le courriel échoue ; essai tracé, alerte au-delà de six mois ; `test_strategie_notification.py` |
| IV.2.3.c à f | Stratégie de notification : incidents à notifier, délai, personnes selon la gravité | Partiel | Criticité minimale par contact ; la stratégie elle-même (délais, revue en comité) est un document du prestataire |
| IV.2.3.g (option A) | La notification ne contient que le numéro du ticket | Couvert | Objet et corps : référence et lien authentifié (`notify.message_for`), `test_notifications.py` |
| IV.2.3.h, j | Registre centralisé et chronologique des notifications par client | Couvert | Registre des notifications par client (date, mode, destinataire, objet, statut, tentatives, code de réponse), JSON et CSV (« Rapports ») |
| IV.2.3.i | Remonter d'une notification au ticket et à son contexte | Couvert | Référence du ticket dans chaque ligne du registre |
| IV.2.3.k | Capacité de stockage des notifications | Couvert | Conservées sans purge ; taille de la base dans le pilotage |
| IV.2.3.l | Portail : voir les tickets et leur statut, suivre et modifier leur état, voir les actions ; récupérer le contexte, déposer des informations | Couvert | État du ticket côté client et demande de clôture ou de réouverture, actions demandées au client, pièces, commentaires ; `test_suivi_client.py`, `99-suivi-client.mjs` |
| IV.3.6 | Plan de sauvegarde et de restauration testé | Partiel | Sauvegarde chiffrée et restauration (`keryx backup`, `keryx restore`) ; plan et tests annuels : organisation |
| IV.3.7.k | Analyses utilisant Internet faites hors du SI du service | Couvert | Keryx n'envoie jamais de fichier à un service en ligne (VirusTotal : empreintes seulement) |
| IV.3.8.g | Cloisonnement entre clients, au minimum logique | Couvert | Contrôle d'accès par client sur chaque requête et chaque export ; tests de cloisonnement (`test_access.py`, `test_wazuh_context.py`, ADR-0031) |
| IV.3.9.c | Journalisation des accès et actions | Couvert | Journal d'audit chaîné (connexions, échecs, verrouillages, déconnexions, actions), export syslog RFC 5424, `verify-audit` ; flux bloqués : infrastructure |
| IV.3.9.d | Annuaire des administrateurs et opérateurs, populations séparées | Partiel | Rôles distincts dans Keryx, realm Keycloak `soc` ; séparation stricte dans l'annuaire : infrastructure |
| IV.3.9.e, g, h | Comptes d'administration dédiés ; moindre privilège ; opérateurs sans droits d'administration | Couvert | Le rôle Admin ne lit aucun ticket ; analyste et manager sans droit d'administration ; accès par client (`test_admin.py`) |
| IV.3.9.k | Échanges chiffrés et authentifiés | Couvert | HTTPS, cookies sécurisés, connecteurs en TLS vérifié ; conformité aux règles cryptographiques de l'ANSSI : à vérifier sur l'infrastructure |
| IV.3.9.o | Écart entre sources de temps connu | Couvert | Écart d'horloge entre manager Wazuh et Keryx affiché (ADR-0028) |
| IV.3.10.a | Seules les interconnexions listées sont permises | Partiel | VirusTotal et les webhooks d'astreinte vers un service hébergé chez un tiers ne sont pas des interconnexions permises : à laisser désactivés dans une architecture qui vise le référentiel (ils le sont par défaut) |
| IV.3.12 | Messagerie de notification dans la zone de notification | Infrastructure | Keryx envoie en SMTP chiffré vers le relais désigné |
| IV.3.13.a | Antivirus dans la zone d'échange, traitement des fichiers chiffrés ou non analysables, journal horodate, nom, empreinte | Couvert | ClamAV et quarantaine chiffrée ; archive chiffrée, endommagée ou illisible classée « non analysable » et isolée ; chaque passage journalisé (`antivirus.analyse`) ; `test_fichiers_non_analysables.py`. Système d'échange du portail séparé : voir ADR-0027 |
| IV.3.13.b | Une machine par client pour le portail, le stockage des incidents et des notifications | Écart | Mode tout-en-un ; séparation décidée (ADR-0027) |
| IV.3.13.c | Annuaire dédié aux clients ; comptes nominatifs, deux facteurs ; authentification mutuelle entre machines | Partiel | Comptes nominatifs, second facteur obligatoire, realm Keycloak `clients` ; authentification mutuelle console et portail : ADR-0027 |
| IV.3.13.e, f | Le client n'accède qu'au nécessaire, sans droit d'administration | Couvert | Rôle Client limité à ses tickets (`test_access.py`) |
| IV.3.13.g | Pare-feu applicatif devant le portail | Écart | Absent du kit ; décidé (ADR-0027, Coraza et OWASP CRS) |
| IV.3.16.f | Recherches en sources ouvertes horodatées et journalisées | Partiel | Recherches VirusTotal journalisées avec l'heure ; elles devraient partir de la zone internet, pas du serveur |
| IV.4.2.f | Recommandé : astreintes | Couvert | Astreinte et escalade (ADR-0032) |
| IV.4.3 | Comités opérationnels et stratégiques | Organisation | Rapports périodiques et pilotage de Keryx comme supports |
| IV.5.1.b | Capitalisation sur les incidents | Partiel | Retour d'expérience obligatoire pour les incidents graves, synthèse (mode opératoire, périmètre) ; le processus est un document du prestataire |
| IV.5.1.e, f, g | Indicateurs opérationnels et stratégiques minimaux | Partiel | Ceux des tickets, des notifications et du portail : couverts (pilotage) ; voir le détail ci-dessous |
| IV.5.2.b | Restituer au client ses données sur demande | Couvert | Export complet d'un client en ZIP avec manifeste d'empreintes, sans secret (manager, `keryx export-client`) ; `test_restitution.py` |
| IV.5.2.f | Détruire les informations du client à la fin | Couvert | `keryx destroy-client` : simulation par défaut, export préalable exigé, fichiers et données supprimés, comptes Client désactivés, journal d'audit |
| IV.5.3.6 | Conservation : 6 mois pour les évènements ; toute la durée de la prestation pour les incidents, leur contexte et les notifications | Couvert | Contexte conservé toute la prestation par défaut ; la purge ne s'applique qu'aux clients pour lesquels l'Admin la choisit ; `test_ops.py` |

### Indicateurs (IV.5.1.e, f, g)

Fournis par Keryx : tickets créés et clos par période, ouverts à ce jour, ouverts par gravité, délais moyens de
qualification et de résolution, respect des échéances, délai d'acquittement par criticité (moyenne et 90e centile),
charge par analyste, disponibilité du parc d'agents, sources muettes, battement de cœur.

Ajoutés le 26/11/2026 (bloc « Indicateurs PDIS » du pilotage) : durées minimale, moyenne et maximale entre création
et clôture ; délai entre détection et notification par gravité ; par mois, créés, clos, incidents avérés, alertes
reçues, ouverts cumulés par criticité et résolution moyenne ; qualification moyenne par typologie et gravité ; 20
règles les plus déclenchées ; comptes et authentifications du portail.

Ajoutés le 27/11/2026 : taille de la base et remplissage du disque des pièces ; réussite de l'envoi des notifications
par mois (disponibilité du système d'envoi). Encore manquant : la disponibilité du portail lui-même, à mesurer par
la supervision de l'infrastructure, ou par la console en mode portail (ADR-0027).

Les indicateurs d'évènements, de collecteurs et de règles relèvent de Wazuh.

## Chapitres hors du logiciel

| Chapitres | Portent sur | Statut |
|---|---|---|
| IV.1 (sauf g) | Personnalité morale, assurance, convention, devoir de conseil | Organisation |
| IV.2.1.a, d, e, f | Incidents redoutés, stratégie d'analyse, règles de classification | Organisation |
| IV.3.1 à IV.3.5 | Appréciation des risques, PSSI, homologation, territorialité, plan de contrôle, sécurité physique | Organisation, Infrastructure |
| IV.3.7 (sauf k) | Service de détection du service lui-même | Organisation, Infrastructure (Keryx peut y être supervisé : journal d'audit en syslog) |
| IV.3.8.a à f | Zones de confiance, matrice des flux, chiffrement IP entre zones | Infrastructure (déploiement de référence : `docs/deploiement-docker.md`) |
| IV.3.9.a, b, f, i, j, l, m | Postes et zones d'administration, zones d'échange, serveur de temps | Infrastructure |
| IV.3.10.b à e, IV.3.11 | Filtrage qualifié, IPsec agréé, zone de mise à jour | Infrastructure |
| IV.3.14, IV.3.15, IV.3.16 (sauf f), IV.3.17 | Enclaves chez le client, zone internet, accès nomades | Infrastructure |
| IV.4.1, IV.4.2 (sauf f), IV.4.3 | Éthique, recrutement, compétences, comités | Organisation |
| IV.5.3 (sauf 6) | Convention de service | Organisation |

Les grilles « guide d'hygiène » et « II 901 » de la trame portent sur l'organisation et l'infrastructure du
prestataire ; Keryx y contribue par sa journalisation, ses comptes nominatifs à second facteur et la séparation des
rôles.

## Écarts du logiciel

Corrigés le 27/11/2026 : fichiers chiffrés ou non analysables (IV.3.13.a), capacité du stockage et envoi des
notifications (IV.2.1.cc, IV.2.3.k). Corrigés le 26/11/2026 : conservation du contexte (IV.5.3.6), contenu du ticket (IV.2.1.w), stratégie, moyen
secondaire et registre des notifications (IV.2.3), état du ticket modifiable par le client (IV.2.3.l), réversibilité
(IV.5.2.b, f), accord du client pour VirusTotal (IV.1.g), verrouillage journalisé (IV.3.9.c), indicateurs de tickets,
de notifications et du portail (IV.5.1).

Restent, dans l'ordre du découpage de l'ADR-0027 :

1. **Portail par client (IV.3.13.b, c)** : une machine par client, authentification mutuelle console et portail.
2. **Pare-feu applicatif (IV.3.13.g)** : Coraza et l'OWASP CRS devant chaque portail.
3. **Disponibilité du portail** (IV.5.1.e, g) : mesurée par la console en mode portail (ADR-0027).
