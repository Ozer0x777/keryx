# Registre des vulnérabilités des composants libres

*In English: record of every known vulnerability found in the open source components shipped with Keryx, and of the
action taken (including "no action needed"), as required by ISO/IEC 18974 (see
`docs/programme-securite-open-source.md`). Audits with no finding are recorded too.*

Tenu par le responsable du programme (`docs/programme-securite-open-source.md`). Une ligne par vulnérabilité ou par
audit sans résultat ; une ligne n'est jamais effacée, sa décision et son état évoluent. Les vulnérabilités du code de
Keryx lui-même suivent `SECURITY.md` et ses avis de sécurité.

États : **ouverte** (à traiter), **corrigée** (commit cité), **acceptée** (risque gardé, raison écrite, revue à la
prochaine revue du programme), **sans objet** (Keryx non touché, raison écrite).

## Vulnérabilités relevées

| N° | Relevée le | Par | Composant et version | Identifiants | Gravité | Décision et action | État |
|---|---|---|---|---|---|---|---|
| V-2026-001 | 24/11/2026 | pip-audit | Pillow 12.3.0 (Python) | Vulnérabilités connues de Pillow 12.3.0 (42 avis relevés par pip-audit) | Plusieurs, jusqu'à élevée | Passage à Pillow 13.0.0 (`requirements.txt`, `requirements.lock`), avant toute publication | corrigée (0501674) |
| V-2026-002 | 25/11/2026 | Grype 0.122.1 | Image 0.8.0 : zlib1g 1:1.3.dfsg+really1.3.1-1+b1 ; libc6 et libc-bin 2.41-12+deb13u4 (Debian 13) | CVE-2026-85091 (zlib) ; CVE-2026-19499 et CVE-2026-5435 (glibc) | Élevée | Correctifs Debian disponibles (zlib 1+deb13u1, glibc 2.41-12+deb13u5) : `apt-get upgrade` ajouté à la construction de l'image ; analyse de l'image ajoutée à la veille et à la publication. L'image 0.8.0 publiée reste touchée jusqu'à la prochaine version | corrigée dans les images 0.8.1 et 0.8.2 ; l'image 0.8.0 reste touchée (mettre à jour, `docs/versions.md`) |
| V-2026-003 | 25/11/2026 | Grype 0.122.1 | Image 0.8.0 : pip 25.0.1 | GHSA-6vgw-5pg2-w6jp, GHSA-jp4c-xjxw-mgf9, GHSA-58qw-9mgm-455v | Moyenne à faible | pip ne sert qu'à l'installation : retiré de l'image après l'installation des dépendances | corrigée dans les images 0.8.1 et 0.8.2 |
| V-2026-004 | 25/11/2026 | Grype 0.122.1 | Image : interpréteur Python 3.12.16 | 9 CVE de gravité moyenne (dont CVE-2025-12781, CVE-2026-6019, CVE-2026-3446), correctif indiqué seulement dans Python 3.13 ou plus récent | Moyenne | Aucun correctif dans la branche 3.12 selon la base de Grype ; à évaluer une par une (fonction touchée utilisée ou non par Keryx) ; piste : passer l'image à Python 3.13. Ne bloque pas la publication (seuil : élevée) | acceptée en attendant l'évaluation (revue suivante) |
| V-2026-005 | 25/11/2026 | OpenSSF Scorecard (OSV) | pytest, borne `>=9` de `requirements-dev.txt` (dépendance de test, non livrée) | PYSEC-2026-1845, CVE-2025-71176, GHSA-6w46-j5rx-g56g | Gestion vulnérable des dossiers temporaires, corrigée en 9.0.3 | Le verrou installe pytest 9.2.0, non touché ; la borne autorisait encore 9.0.0 à 9.0.2 : relevée à `>=9.0.3` | corrigée |

## Audits sans résultat

| Date | Objet | Outils | Résultat |
|---|---|---|---|
| 25/11/2026 | Dépendances de `main` (Python, interface, parcours), tous niveaux de gravité | pip-audit, npm audit | Aucune vulnérabilité connue |
| 25/11/2026 | Dépendances de la version 0.8.0 (Python, interface) | pip-audit, npm audit | Aucune vulnérabilité connue |
| 25/11/2026 | Alertes Dependabot du dépôt depuis leur activation | Dependabot | Aucune alerte émise |
| 25/11/2026 | `main` avant publication de la 0.8.1 : dépendances et image reconstruite | pip-audit, npm audit, Grype 0.118.0 (veille lancée à la main, GitHub Actions) | Aucune vulnérabilité connue dans les dépendances ; aucune vulnérabilité élevée ou critique corrigeable dans l'image |
| 26/11/2026 | `main` avant publication de la 0.8.3 : dépendances (trois verrous Python, npm) et image reconstruite | pip-audit, npm audit, Grype (veille lancée à la main, GitHub Actions) | Aucune vulnérabilité connue dans les dépendances ; aucune vulnérabilité élevée ou critique corrigeable dans l'image |
| 26/11/2026 | `main` avant publication de la 0.8.4 : dépendances (trois verrous Python, npm) et image reconstruite | pip-audit, npm audit, Grype (veille lancée à la main, GitHub Actions) | Aucune vulnérabilité connue dans les dépendances ; aucune vulnérabilité élevée ou critique corrigeable dans l'image |
