# Publication et vérification des images

## Ce qui est publié à chaque version

Quand une étiquette `vX.Y.Z` est poussée, le workflow `.github/workflows/publication.yml` :

1. vérifie que l'étiquette, `keryx/__init__.py`, `web/package.json` et une section `[X.Y.Z]` du `CHANGELOG.md`
   concordent, et que le dépôt ne contient ni secret ni tiret cadratin en Markdown ;
2. construit l'image depuis le `Dockerfile` du dépôt et la publie sur `ghcr.io/<compte>/keryx:X.Y.Z` (pas
   d'étiquette `latest` : on déploie un numéro, pas une cible mouvante) ;
3. attache à l'image une attestation de provenance (SLSA, construite par GitHub Actions depuis ce commit) et une SBOM ;
4. **signe l'image par son empreinte** avec cosign, en signature sans clé : le certificat de signature, émis par
   Sigstore, nomme ce workflow et l'étiquette qui l'a déclenché ;
5. crée la version GitHub avec la section du CHANGELOG, l'empreinte de l'image et une SBOM CycloneDX des dépendances.

## Installer l'image publiée avec le kit Docker

```bash
cd deploy/docker
KERYX_IMAGE=ghcr.io/ozer0x777/keryx KERYX_VERSION=0.8.0 ./install.sh
```

`install.sh` récupère l'image au lieu de la construire, l'inscrit dans `.env`, et vérifie sa signature si `cosign`
est installé ; une signature absente ou invalide arrête l'installation. Sans cosign, il le signale et continue.

## Vérifier une image à la main

```bash
cosign verify ghcr.io/ozer0x777/keryx:0.8.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '(?i)^https://github.com/Ozer0x777/keryx/\.github/workflows/publication\.yml@refs/tags/v'

gh attestation verify oci://ghcr.io/ozer0x777/keryx:0.8.0 --owner Ozer0x777      # provenance
```

Une vérification réussie prouve que l'image a été construite par le workflow de publication de ce dépôt, à partir
d'une étiquette de version. Elle ne prouve pas que le code est exempt de défaut.

## Hors ligne, ou registre interne

Dans un déploiement qui passe par un registre relais (zone de mise à jour, PDIS IV.3.11), vérifier la signature avant
de copier l'image dans le registre interne, puis régler `KERYX_IMAGE` sur le nom interne. Copier par empreinte
(`@sha256:…`), jamais par étiquette seule.

> À COMPLÉTER PAR LE MAINTENEUR : la visibilité du paquet sur ghcr.io doit être réglée sur « public » après la
> première publication (*Packages > keryx > Package settings*), sinon l'image n'est pas récupérable sans compte.
