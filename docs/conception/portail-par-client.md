# Conception : un portail par client (vague 4)

**Statut : proposition, à valider avant tout code.** Ce document décrit comment séparer le portail des clients de la
console d'analyse, pour répondre à PDIS IV.3.13.b. Il ne change rien au code tant qu'il n'est pas validé.

## 1. Le problème

Aujourd'hui, un seul processus Keryx, sur une seule base, sert à la fois l'équipe du SOC (console d'analyse) et les
clients (portail). Le cloisonnement entre clients est logique : chaque requête est filtrée par client
(PDIS IV.3.8.g, « au minimum logique »).

Le référentiel demande davantage pour la partie exposée aux clients :

| Exigence | Texte ou résumé | Source de la lecture |
|---|---|---|
| IV.3.13.b | « Une machine physique ou virtuelle par commanditaire » pour une instance du portail web et de son stockage | lu, cité dans `docs/deploiement-docker.md` |
| IV.3.8.b | Cloisonner le système d'information du service en zones, dont une zone d'échange commanditaire distincte de la zone d'analyse | lu, idem |
| IV.3.8.c | Cloisonnement entre zones « par des mécanismes de filtrage, d'authentification et de contrôle d'accès » | lu, idem |
| IV.3.8.d | Matrice des flux | lu, idem |
| IV.3.13.c | Annuaire dédié aux commanditaires | lu, idem |
| IV.3.13.g | Pare-feu applicatif devant le portail | lu, idem |
| IV.3.13 (autres points) | Contenu exact non relu pour cette conception | **à relire dans le PDF avant validation** |

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
| Comptes clients | Voir la question ouverte n°2 |
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

## 5. Découpage proposé

1. Fonction de projection client unique, utilisée par l'API actuelle (aucun changement visible).
2. Modes `console` et `portail`, routes filtrées par mode.
3. Synchronisation console vers portail (tickets, commentaires, événements visibles), TLS mutuel.
4. Rapatriement des saisies du client (commentaires, pièces), analyse antivirus aux deux bouts.
5. Comptes clients et audit du portail.
6. Kit de déploiement par VM, documentation d'exploitation, mise à jour de la matrice PDIS.

## 6. Questions ouvertes (à trancher par le mainteneur)

1. **Délai de synchronisation** : la console interroge chaque portail toutes les N secondes (proposé : 15 s). Un délai
   plus court charge davantage ; une poussée immédiate des réponses du SOC est faite de toute façon.
2. **Où vivent les comptes clients** : (a) créés depuis la console par l'Admin puis envoyés au portail, le client
   active son compte sur le portail (proposé, une seule administration) ; ou (b) gérés sur chaque portail par un
   administrateur local ; ou (c) un Keycloak par portail.
3. **Base du portail** : PostgreSQL (proposé, comme la console) ou SQLite (plus léger, une VM par client).
4. **Garder le mode tout-en-un** comme mode par défaut (proposé) ou le réserver aux essais.
5. **Relire le chapitre IV.3.13 complet** dans le PDF avant validation ; ce document ne s'appuie que sur les points
   déjà lus et cités dans le dépôt.
