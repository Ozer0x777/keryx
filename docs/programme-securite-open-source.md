# Programme de sécurité des composants libres (ISO/IEC 18974)

*In English: this document is the open source security assurance program of Keryx, written to conform to
ISO/IEC 18974:2023 (OpenChain). It defines the policy, scope, roles, methods and records used to detect and handle
known vulnerabilities in the open source components shipped with Keryx. The last section maps each item of the
OpenChain self-certification checklist to this program. This is a self-certification, not a third-party
certification.*

Ce programme décrit comment Keryx repère et traite les vulnérabilités connues des composants libres qu'il livre. Il
suit la norme ISO/IEC 18974:2023 (OpenChain). La conformité est **déclarée par le projet** (auto-certification) :
ce n'est pas une certification délivrée par un organisme tiers.

## 1. Politique

1. Aucune version de Keryx n'est publiée avec une vulnérabilité connue, de gravité élevée ou critique et
   corrigeable, dans ses composants libres.
2. Chaque composant libre livré est connu : liste complète (SBOM) produite et archivée à chaque version.
3. Les composants sont surveillés en continu, avant et après publication ; chaque vulnérabilité relevée est inscrite
   au registre (`docs/registre-vulnerabilites.md`) avec la décision prise, même quand aucune action n'est nécessaire.
4. Les délais de traitement sont ceux de `SECURITY.md` (correctif sous 30 jours après confirmation pour une
   vulnérabilité critique ou élevée).
5. Les utilisateurs sont informés de toute vulnérabilité qui les touche (avis de sécurité, notes de version).

## 2. Périmètre et limites

**Logiciel livré** (*Supplied Software*) : chaque version publiée de Keryx, c'est-à-dire

- l'image de conteneur `ghcr.io/ozer0x777/keryx:X.Y.Z` : paquets Python (`requirements.lock`), interface web
  construite à partir des paquets npm (`web/package-lock.json`), paquets Debian de l'image de base et du client
  PostgreSQL ;
- l'archive des sources de la version et le kit de déploiement `deploy/docker/`.

**Hors périmètre** : les images tierces que le kit de déploiement télécharge à leur version publiée (PostgreSQL,
Caddy, ClamAV, Garage, Keycloak), qui relèvent de leurs éditeurs ; les dépendances de développement et de test
(`requirements-dev.txt`, `e2e/`), qui ne sont pas livrées mais sont quand même auditées en CI ; Wazuh et les
services externes reliés par l'exploitant.

**Versions suivies** : la dernière version publiée (`SECURITY.md`, « Versions maintenues »).

## 3. Rôles, compétences et participants

| Rôle | Responsabilités | Compétences requises |
|---|---|---|
| Responsable du programme | Tenir ce document et le registre ; trier les alertes ; décider et corriger ; publier les versions et les avis ; revoir le programme | Conception sécurisée et erreurs courantes (OWASP) ; lecture d'un avis CVE ou GHSA et de sa gravité (CVSS) ; outils du programme (pip-audit, npm audit, Dependabot, Grype, CodeQL, cosign) ; gestion des dépendances Python, npm et Debian |
| Contributeur | Justifier toute nouvelle dépendance (`CONTRIBUTING.md`, « Dépendances ») ; ne pas contourner les contrôles de la CI | Savoir lire le résultat des audits de la CI |
| Rapporteur | Signaler en privé une vulnérabilité (`SECURITY.md`) | Aucune exigée |

**Participants au programme** (personnes qui tiennent un rôle du programme) :

| Participant | Rôle | Compétence évaluée |
|---|---|---|
| Ozer0x777 (mainteneur) | Responsable du programme | Auto-évaluation du 25/11/2026 (projet à mainteneur unique) : compétences requises acquises ; conception sécurisée et erreurs courantes déclarées pour le badge OpenSSF Best Practices ; outils du programme mis en place et utilisés dans ce dépôt |

Les contributeurs ponctuels ne sont pas participants : leurs obligations passent par `CONTRIBUTING.md` et par les
contrôles obligatoires de la CI. Un nouveau co-mainteneur (`GOVERNANCE.md`, « Évolution ») devient participant :
il est ajouté à ce tableau, avec sa compétence évaluée, dans la demande de fusion qui lui donne ses droits.

**Moyens** : projet bénévole, sans financement. Le programme repose sur le temps du mainteneur et sur des services
gratuits pour les projets publics (GitHub Actions, Dependabot, CodeQL, signalement privé, ghcr.io). Ces moyens sont
jugés suffisants pour la taille du projet ; ce jugement est revu à chaque revue (section 9). Si une vulnérabilité
dépasse la compétence disponible, le responsable demande l'aide de l'éditeur du composant ou de la communauté, et
le dit dans l'avis.

## 4. Communication et sensibilisation

- Ce document est cité dans le `README.md` (tableau de la documentation), dans `CONTRIBUTING.md` (« Dépendances »)
  et dans `SECURITY.md`. Le modèle de demande de fusion demande à l'auteur de justifier toute nouvelle dépendance.
- Chaque participant connaît : cette politique et son emplacement ; les objectifs (section 5) ; ce qu'on attend de
  lui (section 3) ; les conséquences d'un manquement : une demande de fusion qui ne passe pas les contrôles n'est
  pas fusionnée, une version qui ne passe pas les audits n'est pas publiée, et un participant qui contourne le
  programme perd son rôle (`GOVERNANCE.md`).
- Un nouveau participant lit ce document avant de recevoir ses droits et l'atteste dans sa demande de fusion.

## 5. Objectifs et indicateurs

| Indicateur | Objectif | Valeur au 25/11/2026 |
|---|---|---|
| Vulnérabilités connues élevées ou critiques corrigeables dans la dernière version | 0 | 3 CVE élevées dans l'image 0.8.0 (zlib, glibc : registre V-2026-002), corrigées sur `main`, à publier |
| Délai entre détection et correctif publié (critique ou élevée) | 30 jours au plus | Pillow : 0 jour (corrigé avant publication) |
| Versions publiées avec SBOM archivée | 100 % | 100 % (0.8.0) |
| Veille hebdomadaire exécutée, échec traité sous 7 jours | Chaque semaine | Mise en place le 25/11/2026 |
| Revue du programme | Au moins tous les 12 mois (norme : 18 mois au plus) | Première revue le 25/11/2026 |

## 6. Méthodes

| Besoin | Méthode | Où |
|---|---|---|
| Menaces structurelles et techniques | Modèle de menaces et frontières de confiance, revus quand l'architecture change | `docs/securite.md` (sections 2 à 4), `docs/architecture.md` |
| Détecter les vulnérabilités connues | `pip-audit` (bases OSV et PyPI) sur `requirements.lock`, `requirements-dev.lock` et `requirements-outils.lock` ; `npm audit` (GitHub Advisory) sur l'interface et les parcours ; Grype sur l'image construite (paquets Debian, binaires, Python) ; alertes Dependabot | CI (`ci.yml`, job `audit-dependances`), `veille-vulnerabilites.yml`, `publication.yml` |
| Après publication | Veille chaque lundi sur `main` (dépendances et image reconstruite), alertes Dependabot en continu ; lancement manuel possible | `.github/workflows/veille-vulnerabilites.yml` |
| Évaluer les pratiques du dépôt | OpenSSF Scorecard à chaque modification de `main` et chaque semaine (épinglage des dépendances, permissions, signatures, protection des branches), résultat public | `.github/workflows/scorecard.yml` |
| Tests de sécurité continus avant publication | À chaque demande de fusion : tests, audits, CodeQL, parcours navigateur, contrôles obligatoires sur `main` ; scan OWASP ZAP avant une version | `.github/workflows/ci.yml`, `docs/homologation/dast-zap.md` |
| Vérifier les risques traités avant publication | Le workflow de publication refuse de publier si un audit des dépendances échoue ou si l'image contient une vulnérabilité élevée ou critique corrigeable ; le registre ne doit plus avoir de ligne ouverte bloquante | `.github/workflows/publication.yml` |
| Suivre une vulnérabilité | Inscription au registre, gravité, décision (mettre à jour, contourner, accepter avec raison), correctif dans une demande de fusion, clôture de la ligne avec le commit | `docs/registre-vulnerabilites.md` |
| Informer les utilisateurs | Avis de sécurité GitHub (avec CVE si une version publiée est touchée), section « Sécurité » des notes de version | `SECURITY.md`, `CHANGELOG.md` |
| Transmettre l'information aux tiers | SBOM CycloneDX jointe à chaque version et attestée sur l'image ; avis de sécurité publiés au format GitHub Advisory (repris par OSV) | `docs/publication.md` |

## 7. Questions de tiers sur une vulnérabilité

- **Canal** : signalement privé GitHub (`SECURITY.md`), surveillé par le responsable du programme ; les questions
  publiques sans détail sensible peuvent passer par les issues.
- **Procédure interne** : accusé de réception sous 7 jours ; recherche du composant et de la version dans la SBOM
  de la version concernée et au registre ; réponse sous 14 jours (touché ou non, avec la raison) ; si Keryx est
  touché, inscription au registre et traitement selon `SECURITY.md`.

## 8. Enregistrements

- **Composants livrés** : la SBOM CycloneDX de chaque version (`sbom.cdx.json`) est produite par
  `scripts/sbom.py` et jointe à la version GitHub, avec la SBOM de l'image attestée sur ghcr.io. Les versions ne
  sont jamais supprimées : c'est l'archive des composants de chaque version. Le dépôt garde en plus
  `requirements.lock` et les `package-lock.json` de chaque étiquette.
- **Vulnérabilités** : le registre `docs/registre-vulnerabilites.md` garde chaque vulnérabilité relevée et l'action menée, y compris les audits sans résultat faits à une
  publication ou à une revue. L'historique git du registre date chaque décision.

## 9. Revues

Le programme est revu au moins tous les 12 mois, et à chaque changement important (nouveau participant, nouveau
type de composant livré, incident). La revue vérifie la conformité à la norme (section 10), les indicateurs, les
moyens, et inscrit son résultat ci-dessous ; les changements passent par une demande de fusion.

| Date | Par | Résultat | Trace |
|---|---|---|---|
| 25/11/2026 | Ozer0x777 | Création du programme. Écart trouvé : les paquets Debian de l'image n'étaient pas analysés ; ajout de Grype, mise à jour des paquets à la construction, retrait de pip de l'image. Conformité de la section 10 vérifiée. | Demande de fusion de ce document |

## 10. Conformité à ISO/IEC 18974:2023

Correspondance avec la liste d'auto-certification OpenChain (Generation 2, version 1 du 18/08/2025).

| Exigence | Réponse dans ce programme |
|---|---|
| 4.1.1 Politique documentée | Section 1 |
| 4.1.1 Procédure de communication de la politique | Section 4 |
| 4.1.2 Rôles et responsabilités | Section 3 |
| 4.1.2 Compétences par rôle | Section 3, tableau des rôles |
| 4.1.2 Participants et leur rôle | Section 3, tableau des participants |
| 4.1.2 Compétence évaluée de chaque participant | Section 3, tableau des participants |
| 4.1.2 Trace des revues et changements | Section 9 et historique git |
| 4.1.2 Alignement avec les pratiques et les affectations | Section 9 (revue) |
| 4.1.3 Connaissance de la politique, des objectifs, des contributions attendues, des conséquences d'un manquement | Section 4 |
| 4.1.4 Périmètre et limites écrits | Section 2 |
| 4.1.4 Indicateurs | Section 5 |
| 4.1.4 Preuves de chaque revue | Section 9 |
| 4.1.5 Menaces structurelles et techniques | Section 6 |
| 4.1.5 Détection des vulnérabilités connues | Section 6 |
| 4.1.5 Suivi des vulnérabilités relevées | Section 6 et registre |
| 4.1.5 Communication aux utilisateurs | Section 6 |
| 4.1.5 Analyse après publication | Section 6 (veille hebdomadaire) |
| 4.1.5 Tests de sécurité continus avant publication | Section 6 |
| 4.1.5 Risques traités avant publication | Section 6 (publication bloquée) |
| 4.1.5 Transmission aux tiers | Section 6 |
| 4.2.1 Canal pour les questions de tiers | Section 7 |
| 4.2.1 Procédure interne de réponse | Section 7 |
| 4.2.2 Personnes et fonctions du programme | Section 3 |
| 4.2.2 Rôles pourvus et moyens suffisants | Section 3 (participants, moyens) |
| 4.2.2 Expertise disponible | Section 3 (compétences, recours aux éditeurs) |
| 4.2.2 Attribution interne des responsabilités | Section 3 |
| 4.3.1 Enregistrement continu des composants, archive | Section 8 |
| 4.3.1 Enregistrements qui prouvent l'application | SBOM jointe à chaque version |
| 4.3.2 Procédure de détection et de résolution | Section 6 |
| 4.3.2 Registre des vulnérabilités et des actions | `docs/registre-vulnerabilites.md` |
| 4.4.1 Le programme satisfait toutes les exigences | Cette section, vérifiée à chaque revue |
| 4.4.2 Conformité revue depuis moins de 18 mois | Section 9 |
