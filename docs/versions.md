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

> À COMPLÉTER PAR LE MAINTENEUR : signature des étiquettes, publication d'une image Docker (registre, nom), et
> rythme de publication.

## Versions maintenues

| Version | Correctifs de sécurité |
|---|---|
| 0.8.0 (dernière publiée) et `main` | oui |
| numéros antérieurs (jamais publiés) | non |

> À COMPLÉTER PAR LE MAINTENEUR : durée de maintenance d'une version publiée, si une est promise.
