# Sécurité

*English version below.*

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique pour une vulnérabilité.** Utiliser le signalement privé de GitHub : onglet
*Security* du dépôt, bouton *Report a vulnerability*
(<https://github.com/Ozer0x777/keryx/security/advisories/new>). Le rapport n'est visible que des mainteneurs.

Si le signalement privé est impossible, ouvrir une issue publique qui demande seulement un moyen de contact, sans
aucun détail sur la vulnérabilité.

Joindre si possible : la version ou le commit concerné, le mode de déploiement (Docker, manuel), les étapes pour
reproduire, l'impact estimé (fuite entre clients, élévation de privilèges, contournement de l'audit…). Les rapports
sont acceptés en français et en anglais.

## Délais

| Étape | Délai visé |
|---|---|
| Accusé de réception | 7 jours |
| Première analyse (vulnérabilité confirmée ou non, gravité estimée) | 14 jours |
| Correctif publié, vulnérabilité critique ou élevée | 30 jours après confirmation |
| Correctif publié, autre gravité | 60 jours après confirmation |

Keryx est maintenu par une seule personne, sur son temps libre : ces délais sont des objectifs, pas un contrat. Si un
délai ne peut pas être tenu, le rapporteur en est informé avec la raison et une nouvelle date.

## Publication

- Une vulnérabilité corrigée fait l'objet d'un avis de sécurité GitHub (*security advisory*), avec un identifiant CVE
  demandé par GitHub quand elle touche une version publiée.
- Les notes de version (`CHANGELOG.md`, section « Sécurité ») citent chaque vulnérabilité corrigée, avec son
  identifiant CVE s'il existe.
- Le rapporteur est cité dans l'avis, sauf s'il préfère rester anonyme.
- Les détails ne sont publiés qu'une fois le correctif disponible, ou au plus tard 90 jours après le signalement.

## Versions maintenues

Seule la dernière version publiée et la branche `main` reçoivent des correctifs de sécurité (voir `docs/versions.md`).

## Périmètre

Dans le périmètre : le code de ce dépôt (API, interface, script d'intégration Wazuh, kit de déploiement Docker).
Particulièrement attendus : tout accès d'un client aux données d'un autre client, toute lecture par le rôle Admin du
contenu d'un ticket, toute modification du journal d'audit qui ne casse pas sa chaîne, toute exécution de contenu
d'une pièce déposée.

Hors périmètre : les vulnérabilités de Wazuh, de Keycloak, de PostgreSQL, de Caddy ou de ClamAV eux-mêmes (les
signaler à leurs projets), et un déploiement qui ne suit pas `docs/deploiement-docker.md`.

## Ce que fait déjà le dépôt

À chaque modification, la CI vérifie :
- les tests (SQLite et PostgreSQL) et les parcours dans un navigateur ;
- l'analyse statique : CodeQL, ruff (Python) et ESLint (interface), avertissements traités comme des erreurs ;
- les vulnérabilités connues des dépendances Python et npm ;
- l'absence de secret suivi par git (`scripts/verif_depot.py`).

Dependabot propose chaque semaine les mises à jour des dépendances npm, des actions GitHub et des images Docker ;
les dépendances Python, verrouillées avec empreintes, sont surveillées par les alertes Dependabot et pip-audit. Chaque
image publiée est signée (cosign), accompagnée d'un SBOM et d'une attestation de provenance (`docs/publication.md`).

Les vulnérabilités des composants libres livrés (dépendances, paquets de l'image) suivent le programme
`docs/programme-securite-open-source.md` (ISO/IEC 18974) : veille hebdomadaire, analyse de l'image, publication
bloquée sur une vulnérabilité élevée ou critique corrigeable, registre `docs/registre-vulnerabilites.md`.

---

## Security policy (English)

**Do not open a public issue for a vulnerability.** Use GitHub private vulnerability reporting: *Security* tab,
*Report a vulnerability* (<https://github.com/Ozer0x777/keryx/security/advisories/new>). If that is not possible,
open a public issue asking only for a contact, without any detail. Reports in English or French are welcome.

Target delays: acknowledgement within 7 days, first assessment within 14 days, fix within 30 days of confirmation for
critical or high severity, 60 days otherwise. Keryx has a single volunteer maintainer: these are goals, not a contract;
the reporter is told if a delay slips, with the reason and a new date.

Fixed vulnerabilities get a GitHub security advisory (with a CVE requested through GitHub when a published version is
affected) and are listed in the release notes (`CHANGELOG.md`, "Sécurité" section). Reporters are credited unless they
ask not to be. Only the latest published version and the `main` branch receive security fixes.
