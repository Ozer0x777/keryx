# Sécurité

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique pour une vulnérabilité.** Utiliser le signalement privé de GitHub : onglet
*Security* du dépôt, bouton *Report a vulnerability*. Le rapport n'est visible que des mainteneurs.

> À COMPLÉTER PAR LE MAINTENEUR : activer le signalement privé (*Settings > Code security > Private vulnerability
> reporting*) ; indiquer ici une adresse de contact de repli si le signalement GitHub n'est pas possible.

Joindre si possible : la version ou le commit concerné, le mode de déploiement (Docker, manuel), les étapes pour
reproduire, l'impact estimé (fuite entre clients, élévation de privilèges, contournement de l'audit…).

## Délais

> À COMPLÉTER PAR LE MAINTENEUR : délai d'accusé de réception, délai visé pour un correctif, politique de publication
> (avis de sécurité GitHub, mention dans `CHANGELOG.md`). Aucun engagement n'est pris tant que ces lignes sont vides.

## Versions maintenues

Seule la dernière version de la branche `main` reçoit des correctifs (voir `docs/versions.md`).

## Périmètre

Dans le périmètre : le code de ce dépôt (API, interface, script d'intégration Wazuh, kit de déploiement Docker).
Particulièrement attendus : tout accès d'un client aux données d'un autre client, toute lecture par le rôle Admin du
contenu d'un ticket, toute modification du journal d'audit qui ne casse pas sa chaîne, toute exécution de contenu
d'une pièce déposée.

Hors périmètre : les vulnérabilités de Wazuh, de Keycloak, de PostgreSQL, de Caddy ou de ClamAV eux-mêmes (les
signaler à leurs projets), et un déploiement qui ne suit pas `docs/deploiement-docker.md`.

## Ce que fait déjà le dépôt

À chaque modification, la CI vérifie : les tests (SQLite et PostgreSQL), les vulnérabilités connues des dépendances
Python et npm, l'analyse statique CodeQL, et l'absence de secret suivi par git (`scripts/verif_depot.py`). Dependabot
propose chaque semaine les mises à jour des dépendances, des actions GitHub et des images Docker.
