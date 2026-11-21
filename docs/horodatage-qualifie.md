# Horodatage : choisir et brancher un prestataire qualifié eIDAS de l'UE

*Choix retenu pour la production. La liste de confiance européenne fait foi pour la qualification ; aucun prestataire n'est recommandé ici. Essais réels faits : une autorité locale, FreeTSA (non qualifié) et Certum (autorité de l'UE, point d'accès public, sans authentification) : compatibilité technique démontrée, **qualification non vérifiée**.*

## 1. Choisir
1. Consulter la **liste de confiance européenne** (navigateur « EU Trusted Lists » de la Commission européenne, rubrique eIDAS) et filtrer les services de type « Qualified time-stamp » (QTST) d'un État de l'UE. Un service doit y figurer avec le statut « accordé / en vigueur ».
2. Demander au prestataire : l'**adresse du point d'accès RFC 3161** ; le **mode d'authentification** (identifiant et mot de passe, jeton, ou certificat client) ; l'**OID de la politique** d'horodatage qualifiée ; la **chaîne de certificats** en PEM (racine et intermédiaires) et un moyen de contrôler leurs empreintes hors bande ; le débit, le prix, la disponibilité garantie, la localisation des données (UE).
3. Vérifier que la valeur probante recherchée (présomption d'exactitude de la date, article 41 d'eIDAS) correspond bien à un service **qualifié**, pas seulement « de confiance ».

## 2. Brancher
Variables d'environnement de Keryx :
- `KERYX_TSA_URL` : adresse du service ; `KERYX_TSA_CA_FILE` : fichier PEM de la chaîne du prestataire (contrôler les empreintes avant de s'y fier : c'est la racine de confiance).
- Authentification, selon le prestataire : `KERYX_TSA_USER` + `KERYX_TSA_PASSWORD`, **ou** `KERYX_TSA_BEARER`, **ou** `KERYX_TSA_CLIENT_CERT` (+ `KERYX_TSA_CLIENT_KEY`).
- `KERYX_TSA_POLICY_OID` : OID de la politique qualifiée. Fortement recommandé : Keryx refuse alors toute réponse portant une autre politique.

## 3. Essayer avant de s'engager
`keryx tsa-check` demande un horodatage de test, vérifie la signature et la chaîne, contrôle la politique, et affiche l'heure attestée, le numéro de série et l'OID de politique réellement utilisé (à reporter dans `KERYX_TSA_POLICY_OID`). Échec typique : authentification refusée, chaîne incomplète. Une réponse non conforme au DER strict est acceptée par la vérification de secours d'OpenSSL (voir ADR-0018 ; `openssl` doit être installé).

## 4. Exploiter
Un jeton se télécharge (`.tsr`) et se vérifie hors de Keryx : `openssl ts -verify -in jeton.tsr -data <message> -CAfile chaine.pem`. Conserver les jetons aussi longtemps que la pièce ; prévoir le renouvellement d'horodatage (ré-horodater) avant l'expiration de l'algorithme ou des certificats du prestataire.
