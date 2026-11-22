# ADR-0010 : Verrouillage des comptes et limitation de débit

- **Statut** : accepté (20/11/2026)
- **Décision** : les échecs de mot de passe ne verrouillent pas le compte (un attaquant pourrait bloquer n'importe qui) : ils sont freinés par des limites de débit par adresse IP et par identifiant (réponse 429). Seuls les échecs du second facteur (TOTP), donc après un mot de passe correct, comptent pour le verrouillage : 5 échecs, 15 minutes. Message d'erreur générique dans tous les cas (pas d'énumération des comptes). Sessions : expiration à 8 h et inactivité à 30 min.
- **Exigences** : OWASP ASVS 5.0 chap. 6 (authentification : résistance au bourrage d’identifiants sans déni de service ; numéro exact de l’exigence à vérifier) ; RFC 6585 (429) ; PDIS IV.3.9.d.
- **Limite** : les compteurs de débit sont en mémoire, par processus. Avec plusieurs processus uvicorn ou plusieurs conteneurs, chaque instance compte de son côté. Le MVP tourne avec un seul processus ; un compteur partagé (table `rate_hits`) existe maintenant et s'active par défaut avec PostgreSQL (`KERYX_RATE_LIMIT_BACKEND=db`) ; il est approximatif sous forte concurrence (une requête de plus que la limite peut passer).
