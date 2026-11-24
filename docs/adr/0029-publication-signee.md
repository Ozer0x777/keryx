# ADR-0029 : Publication d'une image signée à chaque version

- **Statut** : accepté (24/11/2026).
- **Contexte** : Keryx est publié en logiciel libre (licence MIT) pour de petits SOC, des MSSP et des CERT. Jusqu'ici,
  chaque installation construisait l'image sur place, depuis le dépôt et des registres publics (Debian, PyPI, npm),
  sans version publiée ni moyen de savoir que l'image installée est celle du projet.
- **Décision** :
  1. Une étiquette `vX.Y.Z` déclenche la publication de `ghcr.io/<compte>/keryx:X.Y.Z` (registre de GitHub, déjà
     utilisé par le projet ; aucun compte supplémentaire). Pas d'étiquette `latest`.
  2. Signature sans clé (cosign, Sigstore) par empreinte, liée à l'identité du workflow : aucune clé privée à
     garder ni à faire tourner. Attestation de provenance et SBOM jointes à l'image ; SBOM CycloneDX jointe à la
     version GitHub.
  3. Le kit Docker garde la construction locale par défaut ; `KERYX_IMAGE` lui fait récupérer l'image publiée et
     vérifier sa signature si cosign est présent.
  4. Numérotation reprise à 0.8.0 : aucune version n'avait été publiée, et le dépôt portait deux numéros (0.2.0
     dans le code, 0.7.0 dans le kit et le dossier d'homologation).
- **Exigences** : PDIS IV.3.11.d (authenticité et intégrité des mises à jour), lue et citée dans
  `docs/deploiement-docker.md` ; la signature y répond pour l'image de Keryx, pas pour les images tierces du kit.
- **Conséquences** : la signature dépend de Sigstore (service public de la Linux Foundation, dont l'hébergement n'est pas garanti dans l'UE) ;
  un déploiement qui ne veut pas de cette dépendance garde la construction locale. Les actions GitHub sont citées
  par version, pas par empreinte : Dependabot les suit.
- **Non essayé** : le workflow ne peut s'exécuter que sur GitHub, à la première étiquette poussée.
