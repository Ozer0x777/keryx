# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Numérotation : voir `docs/versions.md`.

## [Non publié]

### Ajouté
- Vues de priorisation de la file : critiques non assignés, en attente du client, dossiers incomplets (ADR-0025).
- Fiche ticket de l'équipe en cinq onglets avec barre fixe (ADR-0026).
- Indicateur et garde-fou de saisies non enregistrées sur la fiche, brouillon de commentaire dans l'onglet (ADR-0024).
- Confirmations nommant le client avant les étapes qui l'engagent, depuis la fiche et le Kanban (ADR-0024).
- `keryx add-user --password-stdin` ; message clair sans terminal.
- Kit Docker : accès par adresse IPv4 (modes `local` et `fourni`).
- CI : audit des dépendances (pip-audit, npm audit), CodeQL, contrôle des secrets et de la rédaction, tests de
  l'interface ; Dependabot ; `SECURITY.md`, `CONTRIBUTING.md`, modèles d'issue et de demande de fusion.

### Modifié
- Clore en faux positif exige un motif de 10 caractères au moins, interne à l'équipe (le client ne le voit pas).
- Un champ de synthèse sans texte visible est enregistré vide.

### Corrigé
- L'identifiant de connexion est lu sans les espaces de début et de fin.
- Libellés restés en français dans l'interface anglaise (pilotage, rapports).

### Sécurité
- Pillow 12.3.0 vers 13.0.0 : vulnérabilités connues corrigées (relevées par pip-audit).

## [0.2.0] : 2026-11-20

État de départ du dépôt. Les changements entre cette version et la section ci-dessus (audit de sécurité, recherche
VirusTotal, contexte Wazuh, kit Docker, README) sont décrits par l'historique git et les ADR 0021 à 0023.
