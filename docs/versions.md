# Versions

## Numérotation

Keryx suit la gestion sémantique des versions (`MAJEUR.MINEUR.CORRECTIF`). Tant que la version majeure est 0, une
version mineure peut changer l'API ou le schéma de la base ; la migration Alembic correspondante est toujours fournie.

La version est écrite à deux endroits, à garder identiques : `keryx/__init__.py` et `web/package.json`.

## Publier une version

1. Déplacer la section « Non publié » de `CHANGELOG.md` sous le nouveau numéro, avec la date.
2. Mettre à jour les deux numéros de version.
3. CI verte sur `main`, puis étiquette git `vX.Y.Z`.

> À COMPLÉTER PAR LE MAINTENEUR : signature des étiquettes, publication d'une image Docker (registre, nom), et
> rythme de publication.

## Versions maintenues

| Version | Correctifs de sécurité |
|---|---|
| `main` (dernière) | oui |
| 0.2.0 et antérieures | non |

> À COMPLÉTER PAR LE MAINTENEUR : durée de maintenance d'une version publiée, si une est promise.
