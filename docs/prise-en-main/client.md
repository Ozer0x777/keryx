# Fiche client

Ce portail vous montre les incidents de sécurité que le centre de supervision (SOC) a ouverts pour votre
organisation, et seulement eux.

## Première connexion

Vous recevez un identifiant, un mot de passe temporaire et un code d'activation (valable 72 h). À la première
connexion, choisissez votre mot de passe et enregistrez la double authentification dans une application TOTP
(Google Authenticator, Aegis, FreeOTP…). Gardez en lieu sûr les codes de secours affichés une seule fois.

## Suivre un incident

- **Mes incidents** liste vos incidents, leur statut et leur gravité.
- Dans un incident : la description, les éléments déposés, l'historique des étapes, et les **échanges avec le
  SOC**. Vous ne voyez que ce que le SOC a choisi de vous montrer ; ses notes internes restent internes.
- Les statuts : Nouveau, En évaluation (le SOC analyse), En réponse (incident confirmé, actions en cours), Clôturé,
  Retour d'expérience ; ou Faux positif (pas d'incident).

## Votre parc

« Mon parc » liste les machines de votre organisation surveillées par le SOC : celles qui sont actives, celles qui ne
répondent plus et depuis quand, celles dont l'agent Wazuh est en retard de version. Une machine hors ligne n'envoie
plus rien au SOC : si elle doit fonctionner, prévenez votre équipe informatique.

## Répondre au SOC

- Écrivez dans « Votre réponse », puis « Publier ». Votre message est lu par l'équipe qui suit l'incident.
- « Déposer un fichier » transmet un élément (archive ZIP ou image, 20 Mo au plus). Indiquez ce qu'il contient et
  comment vous l'avez obtenu. Chaque fichier est analysé par l'antivirus du SOC.
- Une réponse en cours de rédaction est gardée dans l'onglet de votre navigateur tant que vous ne l'avez pas publiée.

## Sécurité

- Ne transmettez jamais un mot de passe par ce portail.
- « Mon profil » liste vos sessions actives : fermez celle que vous ne reconnaissez pas et prévenez votre contact
  au SOC. Vous y changez aussi votre mot de passe et vos codes de secours.
