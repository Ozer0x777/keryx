# Conception : un portail par client (vague 4)

**Statut : décisions prises le 26/11/2026 (section 6), après lecture intégrale du référentiel PDIS v2.0 du
21/12/2017 (chapitres I à IV, annexes 1 à 5).** Ce document décrit comment séparer le portail des clients de la
console d'analyse. Le code se fera dans l'ordre de la section 5.

## 1. Le problème

Aujourd'hui, un seul processus Keryx, sur une seule base, sert à la fois l'équipe du SOC (console d'analyse) et les
clients (portail). Le cloisonnement entre clients est logique : chaque requête est filtrée par client
(PDIS IV.3.8.g, « au minimum logique »).

Le référentiel demande davantage pour la partie exposée aux clients :

Exigences lues dans le référentiel (résumées ; le texte fait foi) :

| Exigence | Ce qu'elle demande | Effet sur la conception |
|---|---|---|
| IV.3.8.b, c | Zones de confiance cloisonnées par filtrage, authentification et contrôle d'accès, dont une zone d'échange commanditaire distincte de la zone d'analyse | modes `console` et `portail` |
| IV.3.8.d | Matrice des flux de référence, seuls les flux strictement nécessaires | une seule interface de synchronisation, flux ouverts par la console |
| IV.3.8.e, IV.3.10.c | Chiffrement et authentification IP agréés entre zones et avec le SI du commanditaire | relève de l'infrastructure (IPsec agréé) : le TLS mutuel de Keryx s'y ajoute, il ne le remplace pas |
| IV.3.8.g | Cloisonnement entre commanditaires des tickets, notifications et portail, au minimum logique | physique pour le portail (une VM par client), logique dans la console |
| IV.3.9.c | Journaliser tous les accès et actions | audit du portail rapatrié par la console |
| IV.3.9.d | Annuaire des administrateurs et opérateurs, populations séparées | distinct de l'annuaire des clients (IV.3.13.c) |
| IV.3.12 | Messagerie de notification dans la zone de notification, flux sortants seulement | la console envoie par un relais de cette zone, jamais le portail |
| IV.3.13.a | Portail (voir et mettre à jour l'état des incidents et des actions engagées) et stockage (contexte des incidents, dépôts du client), selon le « système d'échange » de la note [NT_ADMIN] ; analyse antivirus, traitement spécifique des fichiers chiffrés ou non analysables, journal de l'horodate, du nom et de l'empreinte de chaque fichier analysé | décisions 5 et 6 |
| IV.3.13.b | Une machine physique ou virtuelle par commanditaire pour le portail **et** le stockage des incidents **et des notifications** | le portail reçoit aussi le registre des notifications du client |
| IV.3.13.c | Annuaire dédié aux commanditaires ; comptes nominatifs, deux facteurs pour une personne, authentification mutuelle entre machines ; liste à jour des comptes et de leurs privilèges | décision 2 |
| IV.3.13.d | Recommandé : certificats RGS*** et supports qualifiés | non retenu au départ (recommandation) ; possible plus tard |
| IV.3.13.e, f | Le client n'accède qu'au nécessaire et n'a aucun droit d'administration ou d'exploitation | le mode `portail` ne sert que les routes du rôle Client |
| IV.3.13.g | Pare-feu applicatif devant le portail | décision 7 |
| IV.3.13.h | Filtrage entre la zone d'échange et le SI du client : enclave de consultation et postes nomades seulement | relève de l'infrastructure, décrit dans le kit |
| IV.2.3.g, h, j | Notification : numéro du ticket seulement ; registre des notifications | inchangé (déjà le cas), copié vers le portail |
| IV.2.3.l | Portail : voir et mettre à jour l'état des incidents et des actions engagées ; dépôt et récupération de contexte | décision 6 |
| IV.5.1.e, g | Indicateurs : disponibilité du portail, échecs et succès d'authentification à la zone d'échange, comptes du portail créés et supprimés par mois | décision 8 |

Déployer un Keryx complet par client ne répond pas : la console des analystes et toutes les données internes
(alertes brutes, commentaires internes, audit de l'équipe) se retrouveraient dans la zone exposée, et les analystes
auraient un écran par client.

## 2. Proposition

```
 ZONE D'ANALYSE                                   ZONE D'ÉCHANGE COMMANDITAIRE
 ┌──────────────────────────────┐                 ┌─────────────────────────────────────┐
 │ Keryx « console »            │   mTLS, flux    │ VM ACME : Keryx « portail » ACME    │
 │  tous les clients            │   à l'initiative│  base ACME, pièces ACME             │
 │  équipe seulement            ├────────────────▶│  comptes ACME seulement             │
 │  base complète, audit        │   de la console │ VM DELTA : Keryx « portail » DELTA  │
 │                              ├────────────────▶│  …                                  │
 └──────────────────────────────┘                 └─────────────────────────────────────┘
                                                     ▲ pare-feu applicatif (IV.3.13.g)
                                                     │ navigateurs des clients
```

1. **Un seul code, deux modes.** Le même Keryx démarre soit en mode `console` (zone d'analyse : équipe seulement, le
   rôle Client y est refusé), soit en mode `portail` pour **un** client (zone d'échange : rôle Client seulement).
   Le mode actuel, tout-en-un, reste le mode par défaut pour un petit SOC qui ne vise pas la qualification.
2. **Le portail ne détient que ce que le client voit déjà.** La donnée copiée vers un portail est exactement la
   « projection client » que l'API renvoie aujourd'hui au rôle Client : champs du ticket visibles du client,
   commentaires et événements marqués visibles, pièces marquées visibles et leur chaîne de possession, comptes du
   client. Jamais : alertes brutes, commentaires internes, motif du faux positif, échéances internes, contexte Wazuh,
   VirusTotal, synthèse interne, audit de l'équipe, autres clients. Une seule fonction calcule cette projection, et
   l'API du mode tout-en-un l'utilise aussi : ce que voit le client et ce que reçoit le portail ne peuvent pas
   diverger.
3. **Les flux partent toujours de la console.** La zone d'analyse n'accepte aucune connexion venant de la zone
   d'échange. La console pousse les projections vers chaque portail et vient y chercher ce que le client a saisi
   (commentaires, pièces déposées). Un portail compromis ne peut donc rien ouvrir vers la zone d'analyse.
4. **Authentification mutuelle des machines** (IV.3.8.c) : TLS mutuel. Chaque portail a un certificat serveur et
   n'accepte sur son interface de synchronisation que le certificat client de la console ; la console vérifie que le
   certificat du portail porte la clé du client attendu. Une autorité interne dédiée signe ces certificats. Les
   messages portent un numéro de version par objet : un rejeu ou un message en retard est ignoré.
5. **Les saisies du client sont rapatriées et contrôlées.** Une pièce déposée sur le portail est analysée sur place
   (ClamAV), puis rapatriée par la console, qui vérifie son empreinte et la réanalyse avant de l'inscrire au registre.
   Un commentaire du client est assaini au portail et de nouveau à la console.
6. **Audit en deux parties.** Chaque portail tient sa propre chaîne d'audit (connexions et actions de ses comptes) ;
   la console la rapatrie et vérifie son scellement. L'audit de l'équipe ne quitte jamais la zone d'analyse.
7. **Notifications** : envoyées par la console via la zone de notification, comme aujourd'hui, jamais par un portail.

## 3. Ce qui change dans Keryx

| Partie | Changement |
|---|---|
| Configuration | `KERYX_MODE` (`tout-en-un` par défaut, `console`, `portail`), `KERYX_PORTAIL_CLIENT` (clé du client servi), certificats de synchronisation |
| API | Fonction unique de projection client ; en mode `portail`, seules les routes du rôle Client répondent ; nouvelles routes de synchronisation, servies sur une interface séparée en TLS mutuel |
| Console | Tâche de synchronisation par portail : file d'envoi persistante, reprise après coupure, état visible par l'Admin (dernier échange réussi, retard) |
| Base | Table de suivi des versions envoyées par objet et par portail ; aucune autre migration du modèle existant |
| Comptes clients | Cycle de vie dans la console, secrets sur le portail seulement (décision 2) |
| Kit Docker | Un `compose` « portail » à déployer dans chaque VM client ; le `compose` actuel devient la console |

## 4. Ce qui sera testé

- Le portail d'un client ne contient aucune donnée interne : recherche, dans sa base et son stockage, d'un
  commentaire interne, d'un motif de faux positif et d'une alerte brute créés pour le test.
- Le portail ACME ne reçoit jamais rien de DELTA, même si la console se trompe d'adresse (certificat refusé).
- Une connexion de synchronisation sans certificat, ou avec le certificat d'un autre portail, est refusée.
- Un rejeu d'un ancien message ne fait pas revenir en arrière un ticket.
- Coupure du portail pendant une heure : rien n'est perdu, tout est rattrapé dans l'ordre.
- Une pièce EICAR déposée sur le portail est mise en quarantaine sur place et n'atteint pas la console en clair.
- Le mode tout-en-un garde exactement son comportement (toute la suite actuelle passe sans changement).
- La notification au client part après l'accusé de réception du portail, ou au bout de 2 minutes avec la mention
  « portail en retard ».
- Aucun secret de compte client n'existe dans la base de la console.
- Une archive ZIP chiffrée déposée est classée « non analysable » et isolée ; chaque passage par l'antivirus est
  journalisé avec horodate, nom et empreinte.
- Le parcours e2e complet du rôle Client passe derrière Coraza et l'OWASP CRS en mode blocage.

## 5. Découpage

1. Fonction de projection client unique, utilisée par l'API actuelle (aucun changement visible).
2. Liste des exigences PDIS non couvertes en mode tout-en-un (décision 4).
3. État du ticket côté client et actions demandées au client, utilisables en tout-en-un (décision 6).
4. Fichiers chiffrés ou non analysables, journal de passage à l'antivirus (décision 5) : fait le 27/11/2026.
5. Modes `console` et `portail`, routes filtrées par mode.
6. Synchronisation console vers portail (tickets, commentaires, événements, notifications visibles), TLS mutuel,
   notification après accusé de réception (décision 1).
7. Rapatriement des saisies du client (commentaires, pièces, état des actions).
8. Comptes clients activés sur le portail, audit et indicateurs du portail (décisions 2 et 8).
9. Kit de déploiement par VM (SQLite, Caddy avec Coraza et l'OWASP CRS), matrice des flux, documentation
   d'exploitation, mise à jour de la matrice PDIS.

## 6. Décisions (26/11/2026)

Prises par délégation du mainteneur, après lecture intégrale du référentiel.

1. **Synchronisation.** La console pousse aussitôt chaque changement visible du client. Elle n'envoie la
   notification au client (qui ne contient que le numéro du ticket, IV.2.3.g) qu'après l'accusé de réception du
   portail : sinon le client reçoit un numéro qu'il ne peut pas consulter. Si le portail ne répond pas dans les
   2 minutes, la notification part quand même et le registre le note (« portail en retard »). La console vient
   chercher les saisies du client toutes les 15 secondes (réglable de 5 à 300) et juste après chaque poussée.
2. **Comptes des clients.** Le cycle de vie (création, privilèges, désactivation) se décide dans la console, par
   l'Admin, qui tient le rôle de « responsable des droits d'accès » (annexe 2, VI) et la liste des comptes et de
   leurs privilèges (IV.3.13.c). Les secrets (mot de passe, second facteur TOTP ou WebAuthn) sont créés par le client
   sur le portail, à l'activation, avec un code à usage unique remis hors bande, et ne sont stockés que sur le
   portail : c'est l'annuaire dédié aux clients, distinct de celui de l'équipe (IV.3.9.d). La console ne reçoit
   jamais un secret de client. Écartés : un administrateur par portail (une administration de plus par client) et
   un Keycloak par portail (un composant lourd de plus par VM, non exigé). Le realm Keycloak `clients` du kit
   tout-en-un (ADR-0023) n'est pas utilisé en mode `portail` : il vit hors de la zone d'échange.
3. **Base du portail : SQLite** (mode WAL, un seul processus), PostgreSQL restant possible par
   `KERYX_DATABASE_URL`. Un portail ne sert qu'un client, peu d'utilisateurs : moins de composants à durcir, mettre à
   jour et auditer dans chaque VM (IV.3.2.b, IV.3.4.e), et une sauvegarde réduite à la base et aux pièces (IV.3.6).
   La tenue en charge sera mesurée dans les tests.
4. **Le mode tout-en-un reste le mode par défaut** : le projet vise d'abord les petits SOC, qui ne cherchent pas la
   qualification. Il ne répond pas au cloisonnement en zones du référentiel ; Keryx publiera la liste des exigences
   PDIS qu'il ne couvre pas dans ce mode, comme le référentiel recommande de la demander pour une prestation non
   qualifiée (III.3, annexe 3 I.d). Les modes `console` et `portail` servent aux déploiements qui visent
   l'architecture du référentiel.
5. **Fichiers.** Toute pièce traverse l'antivirus aux deux bouts (dépôt sur le portail, arrivée dans la console). Une
   archive chiffrée ou un fichier que l'antivirus ne peut pas analyser reçoit un statut « non analysable » et suit le
   traitement de la quarantaine : jamais ouvert en clair sur un poste sans action explicite et tracée. Chaque
   passage par l'antivirus est journalisé avec l'horodate, le nom et l'empreinte SHA-256, dans les deux sens
   (IV.3.13.a). Fait en mode tout-en-un le 27/11/2026 (statut « non analysable », journal `antivirus.analyse`).
   Le PDIS renvoie au chapitre « Système d'échange » de [NT_ADMIN] ; lu dans sa version actuelle (guide
   ANSSI-PA-022 v3.0, chapitre 11, R52 à R58) : protocoles de transfert seulement, à l'initiative de clients situés
   hors du système d'échange (R54) ; accès limité au besoin (R55) ; aucun compte d'administration (R56) ; aucun
   stockage durable, suppression dès le transfert ou sous 24 h environ (R57) ; analyse de tout ce qui transite (R58).
   Pour le portail séparé : un dépôt du client est supprimé du portail dès que la console l'a rapatrié et inscrit au
   registre (R57) ; le contexte que le portail met à disposition du client (IV.2.3.l) n'est pas un transit et reste.
6. **Ce que le client met à jour.** La trame d'évaluation (IV.2.3.l) vérifie que le portail permet « le suivi et la
   modification de l'état des tickets » et la vue des actions. Le client modifie donc l'état de ses tickets sur un
   cycle qui lui est propre : « pris en compte », « en cours de traitement chez nous », « traité de notre côté »,
   avec une demande de clôture ou de réouverture. Chaque changement est inscrit au registre des actions et signalé à
   l'équipe ; la qualification, la gravité et la clôture du ticket restent à l'équipe, qui accepte ou refuse la
   demande. Le client met aussi à jour l'état des actions que l'équipe lui demande (« à faire », « faite »,
   « impossible », avec un commentaire), commente et dépose des informations de contexte. Ces ajouts au modèle
   servent aussi en mode tout-en-un.
7. **Pare-feu applicatif** devant chaque portail (IV.3.13.g) : Coraza avec l'OWASP Core Rule Set, en mode blocage,
   intégré au mandataire Caddy du kit « portail ». Les parcours e2e du rôle Client passent au travers, pour détecter
   les faux positifs avant la mise en service.
8. **Indicateurs** (IV.5.1.e, g) : la console calcule la disponibilité de chaque portail à partir des
   synchronisations, et rapatrie les succès et échecs d'authentification et les comptes créés et supprimés par mois.
9. **Hors de Keryx, à la charge de l'infrastructure** et décrit dans le kit : IPsec agréé entre zones et avec le SI du
   client (IV.3.8.e, IV.3.10.c), filtrage qualifié aux interconnexions (IV.3.10.b, IV.3.13.h), relais de messagerie
   dans la zone de notification (IV.3.12). Dans une architecture qui vise le référentiel, les canaux d'astreinte
   (ADR-0032) restent internes : un service de discussion hébergé chez un tiers n'est pas une interconnexion permise
   par IV.3.10.a.
