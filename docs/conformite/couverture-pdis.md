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
| IV.1.g | Consentement du client avant toute communication d'informations | Écart | La recherche VirusTotal (désactivée par défaut) envoie des empreintes à un tiers sans autorisation enregistrée du client |
| IV.2.1.b, c | Catégories d'incidents redoutés ; recommandé : ETSI GS ISI | Partiel | Classification ETSI GS ISI sur le ticket (`routes_isi.py`) ; la liste des incidents redoutés est un document du prestataire |
| IV.2.1.g à p | Règles de détection : marquage, liste versionnée, bulletin mensuel, registre des ajouts | Wazuh | Les règles vivent dans Wazuh ; Keryx ne tient ni liste versionnée ni bulletin d'état des règles |
| IV.2.1.q, r | Qualification (véracité, gravité) selon une échelle établie avec le client | Couvert | Verdict, dommages et importance, grille de gravité par client (`severity.py`), gravité proposée (ADR-0028) |
| IV.2.1.s | Recommandé : échelle de gravité de l'annexe C d'ISO/IEC 27035 | Partiel | Échelle à quatre niveaux propre à Keryx, réglable par client ; non alignée mot pour mot sur l'annexe C |
| IV.2.1.t, u | Recherche en sources ouvertes : méthode, marquage, prudence | Partiel | Recherches VirusTotal tracées au journal d'audit ; le marquage des règles n'est pas consulté ; la requête part du serveur (voir IV.3.10.a) |
| IV.2.1.w | Contenu minimal du ticket | Partiel | Présents : création et registre des actions, date de détection, description, gravité, impact, risque induit, identifiant de règle, équipement source, identifiants des évènements. **Manquent** : niveau de classification IGI 1300 / II 901 (le TLP n'en tient pas lieu), numéro de version de la règle, collecteur (manager Wazuh) affiché sur le ticket |
| IV.2.1.x, y | Format des tickets défini avec le client ; recommandé : ETSI GS ISI | Partiel | Export IODEF (RFC 7970) ; classification ETSI GS ISI ; format à fixer dans la convention |
| IV.2.1.z | Outil de gestion des tickets dans la zone d'analyse | Couvert | Keryx |
| IV.2.1.aa | Contexte stocké avec le ticket, quel que soit son état | Partiel | Alertes brutes avec empreinte, pièces, synthèse, retour d'expérience ; mais la rétention purge les alertes brutes des tickets clos (voir IV.5.3.6) |
| IV.2.1.bb | Registre centralisé et chronologique par client | Couvert | `GET /api/v1/registre` (CSV), `test_reports.py` |
| IV.2.1.cc | Capacité de stockage des tickets suivie | Partiel | Espace disque des pièces dans l'état du système ; pas de suivi du remplissage de la base |
| IV.2.1.dd, ee | Analyse a posteriori, recherche d'indicateurs sur 6 mois | Wazuh | Indexeur Wazuh ; Keryx lit le contexte d'un agent (ADR-0021), il ne cherche pas dans tout l'historique |
| IV.2.2 (sauf r, s) | Stratégie et capacité de collecte, collecteurs, indexation | Wazuh | |
| IV.2.2.r | Le collecteur détecte une perte de communication | Partiel | Battement de cœur de la chaîne (ADR-0032) : complément de bout en bout, la détection au collecteur reste à Wazuh |
| IV.2.2.s | Chaque évènement associé à son collecteur | Wazuh | Keryx conserve `manager.name` dans l'alerte brute |
| IV.2.3.a, b | Canal de notification et canal sécurisé ; deux moyens de notification, le secondaire testé tous les six mois | Écart | Un seul moyen : le courriel aux contacts du client. Pas de moyen secondaire (SMS, téléphone, autre), pas de test tracé |
| IV.2.3.c à f | Stratégie de notification : incidents à notifier, délai, personnes selon la gravité | Écart | Tous les contacts reçoivent tous les tickets ; pas de destinataires ni de délais par gravité |
| IV.2.3.g (option A) | La notification ne contient que le numéro du ticket | Couvert | Objet et corps : référence et lien authentifié (`notify.message_for`), `test_notifications.py` |
| IV.2.3.h, j | Registre centralisé et chronologique des notifications par client | Partiel | Table `notifications` (date, canal, destinataire, contenu, statut, tentatives) et journal d'audit ; **aucun écran ni export** pour l'opérateur |
| IV.2.3.i | Remonter d'une notification au ticket et à son contexte | Partiel | Lien en base (`ticket_id`) ; pas d'écran |
| IV.2.3.k | Capacité de stockage des notifications | Partiel | Conservées sans purge ; pas d'indicateur |
| IV.2.3.l | Portail : voir les tickets et leur statut, **suivre et modifier leur état**, voir les actions ; récupérer le contexte, déposer des informations | Écart | Présents : vue des tickets, statut, actions visibles, pièces visibles, dépôt de pièces, commentaires. **Manque** : la modification de l'état d'un ticket par le client |
| IV.3.6 | Plan de sauvegarde et de restauration testé | Partiel | Sauvegarde chiffrée et restauration (`keryx backup`, `keryx restore`) ; plan et tests annuels : organisation |
| IV.3.7.k | Analyses utilisant Internet faites hors du SI du service | Couvert | Keryx n'envoie jamais de fichier à un service en ligne (VirusTotal : empreintes seulement) |
| IV.3.8.g | Cloisonnement entre clients, au minimum logique | Couvert | Contrôle d'accès par client sur chaque requête et chaque export ; tests de cloisonnement (`test_access.py`, `test_wazuh_context.py`, ADR-0031) |
| IV.3.9.c | Journalisation des accès et actions | Partiel | Journal d'audit chaîné (connexions, échecs, déconnexions, actions), export syslog RFC 5424, `verify-audit` ; **le verrouillage d'un compte n'a pas d'entrée propre** ; flux bloqués : infrastructure |
| IV.3.9.d | Annuaire des administrateurs et opérateurs, populations séparées | Partiel | Rôles distincts dans Keryx, realm Keycloak `soc` ; séparation stricte dans l'annuaire : infrastructure |
| IV.3.9.e, g, h | Comptes d'administration dédiés ; moindre privilège ; opérateurs sans droits d'administration | Couvert | Le rôle Admin ne lit aucun ticket ; analyste et manager sans droit d'administration ; accès par client (`test_admin.py`) |
| IV.3.9.k | Échanges chiffrés et authentifiés | Couvert | HTTPS, cookies sécurisés, connecteurs en TLS vérifié ; conformité aux règles cryptographiques de l'ANSSI : à vérifier sur l'infrastructure |
| IV.3.9.o | Écart entre sources de temps connu | Couvert | Écart d'horloge entre manager Wazuh et Keryx affiché (ADR-0028) |
| IV.3.10.a | Seules les interconnexions listées sont permises | Partiel | VirusTotal et les webhooks d'astreinte vers un service hébergé chez un tiers ne sont pas des interconnexions permises : à laisser désactivés dans une architecture qui vise le référentiel (ils le sont par défaut) |
| IV.3.12 | Messagerie de notification dans la zone de notification | Infrastructure | Keryx envoie en SMTP chiffré vers le relais désigné |
| IV.3.13.a | Antivirus dans la zone d'échange, traitement des fichiers chiffrés ou non analysables, journal horodate, nom, empreinte | Partiel | ClamAV et quarantaine chiffrée ; empreinte et chaîne de possession par pièce ; **archive chiffrée sans traitement propre** |
| IV.3.13.b | Une machine par client pour le portail, le stockage des incidents et des notifications | Écart | Mode tout-en-un ; séparation décidée (ADR-0027) |
| IV.3.13.c | Annuaire dédié aux clients ; comptes nominatifs, deux facteurs ; authentification mutuelle entre machines | Partiel | Comptes nominatifs, second facteur obligatoire, realm Keycloak `clients` ; authentification mutuelle console et portail : ADR-0027 |
| IV.3.13.e, f | Le client n'accède qu'au nécessaire, sans droit d'administration | Couvert | Rôle Client limité à ses tickets (`test_access.py`) |
| IV.3.13.g | Pare-feu applicatif devant le portail | Écart | Absent du kit ; décidé (ADR-0027, Coraza et OWASP CRS) |
| IV.3.16.f | Recherches en sources ouvertes horodatées et journalisées | Partiel | Recherches VirusTotal journalisées avec l'heure ; elles devraient partir de la zone internet, pas du serveur |
| IV.4.2.f | Recommandé : astreintes | Couvert | Astreinte et escalade (ADR-0032) |
| IV.4.3 | Comités opérationnels et stratégiques | Organisation | Rapports périodiques et pilotage de Keryx comme supports |
| IV.5.1.b | Capitalisation sur les incidents | Partiel | Retour d'expérience obligatoire pour les incidents graves, synthèse (mode opératoire, périmètre) ; le processus est un document du prestataire |
| IV.5.1.e, f, g | Indicateurs opérationnels et stratégiques minimaux | Partiel | Voir le détail ci-dessous |
| IV.5.2.b | Restituer au client ses données sur demande | Écart | Registre CSV et export IODEF par ticket ; **pas d'export complet d'un client** (tickets, contexte, pièces, notifications) |
| IV.5.2.f | Détruire les informations du client à la fin | Écart | Pas de destruction complète et tracée d'un client |
| IV.5.3.6 | Conservation : 6 mois pour les évènements ; **toute la durée de la prestation** pour les incidents, leur contexte et les notifications | Écart | La rétention supprime les alertes brutes (contexte) des tickets clos après le délai du client (6 mois au moins) ; aucun réglage « toute la prestation » |

### Indicateurs (IV.5.1.e, f, g)

Fournis par Keryx : tickets créés et clos par période, ouverts à ce jour, ouverts par gravité, délais moyens de
qualification et de résolution, respect des échéances, délai d'acquittement par criticité (moyenne et 90e centile),
charge par analyste, disponibilité du parc d'agents, sources muettes, battement de cœur.

Manquants, côté tickets et notifications :

- durées minimale et maximale entre création et clôture ;
- tickets ouverts cumulés par mois et par criticité, et leur évolution ;
- incidents avérés par mois ;
- alertes reçues par mois (occurrences comprises) et classement des 20 règles les plus déclenchées ;
- durée moyenne de qualification par typologie d'incident et par gravité ;
- délais minimal, moyen et maximal entre détection et notification, par gravité ;
- remplissage et capacité restante du stockage des incidents et des notifications ;
- comptes du portail : nombre, créés et supprimés par mois ; succès et échecs d'authentification au portail ;
- disponibilité du portail et du système d'envoi des notifications.

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

## Écarts du logiciel, par priorité

1. **Conservation (IV.5.3.6, IV.2.1.aa)** : réglage par client « conserver le contexte pendant toute la prestation »
   (aucune purge des alertes brutes de ses tickets), à activer pour une prestation qui vise le référentiel.
2. **Contenu du ticket (IV.2.1.w)** : niveau de classification (non protégé, Diffusion Restreinte, réglable par
   client et par ticket), numéro de version de la règle, collecteur affiché.
3. **Notifications (IV.2.3.a à f, h, j)** : destinataires et délais par gravité, moyen secondaire (réutiliser les
   canaux de l'astreinte : webhook vers un service de SMS ou d'appel) avec un test tracé, écran et export du registre
   des notifications par client.
4. **État du ticket modifiable par le client (IV.2.3.l)** : voir la décision 6 de l'ADR-0027.
5. **Réversibilité (IV.5.2.b, f)** : export complet d'un client (tickets, contexte, pièces, notifications, journal)
   et destruction complète, tracée, en fin de prestation.
6. **VirusTotal (IV.1.g, IV.2.1.t, IV.3.10.a)** : autorisation par client, refusée par défaut ; documentation : à
   désactiver, ou à faire passer par la zone internet, dans une architecture qui vise le référentiel.
7. **Journalisation (IV.3.9.c)** : entrée d'audit propre au verrouillage d'un compte.
8. **Indicateurs (IV.5.1.e, f, g)** : ceux de la liste ci-dessus.
9. **Fichiers chiffrés (IV.3.13.a)**, **pare-feu applicatif (IV.3.13.g)** et **portail par client (IV.3.13.b)** :
   ADR-0027.
