# Versions

## Numérotation

Keryx suit la gestion sémantique des versions (`MAJEUR.MINEUR.CORRECTIF`). Tant que la version majeure est 0, une
version mineure peut changer l'API ou le schéma de la base ; la migration Alembic correspondante est toujours fournie.

La version est écrite à deux endroits, à garder identiques : `keryx/__init__.py` et `web/package.json`.

## Publier une version

1. Déplacer la section « Non publié » de `CHANGELOG.md` sous le nouveau numéro, avec la date.
2. Mettre à jour les numéros de version (`keryx/__init__.py`, `web/package.json` et `web/package-lock.json`).
3. CI verte sur `main`, puis pousser l'étiquette git `vX.Y.Z`. Le workflow `publication.yml` vérifie que les numéros
   concordent, publie l'image signée sur `ghcr.io` et crée la version GitHub (voir `docs/publication.md`).

Les étiquettes git ne sont pas signées ; l'image publiée l'est (cosign, signature liée au workflow de publication,
voir `docs/publication.md`). Image : `ghcr.io/ozer0x777/keryx:X.Y.Z`. Pas de rythme fixe : une version sort quand des
changements utiles sont prêts, et sans attendre quand elle corrige une vulnérabilité.

Les notes de version (`CHANGELOG.md`) ont une section « Sécurité » qui cite chaque vulnérabilité corrigée, avec son
identifiant CVE s'il existe (voir `SECURITY.md`).

## Versions maintenues

| Version | Correctifs de sécurité |
|---|---|
| 0.9.0 (dernière publiée) et `main` | oui |
| 0.8.4 | non : mettre à jour vers 0.9.0 (migrations de base 0022 à 0025 appliquées par l'image au démarrage) |
| 0.8.3 | non : mettre à jour vers 0.9.0 (cloisonnement d'un indexeur Wazuh partagé, correctifs de sécurité, voir `CHANGELOG.md`) |
| 0.8.2 | non : mettre à jour vers 0.9.0 (correctif de l'ingestion d'une alerte contenant un caractère nul, voir `CHANGELOG.md`) |
| 0.8.1 | non : publication incomplète (image seule), mettre à jour vers 0.9.0 |
| 0.8.0 | non : mettre à jour vers 0.9.0 (image touchée par des failles élevées de Debian, voir `CHANGELOG.md`) |
| numéros antérieurs (jamais publiés) | non |

Aucune durée de maintenance n'est promise pour une version ancienne : un correctif de sécurité sort dans une
nouvelle version, et il faut mettre à jour vers celle-ci.
