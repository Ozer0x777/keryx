# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Numérotation : voir `docs/versions.md`.

## [Non publié]

### Ajouté
- Liste des tickets paginée : 25, 50 ou 100 par page, page et taille de page dans l'URL (retour depuis une fiche,
  bouton Précédent du navigateur, lien partagé), retour à la page 1 quand un filtre change, barre de pages commune
  (`web/src/components/Pager.jsx`) ; auparavant, 200 tickets au plus étaient affichés.
- Parc d'agents paginé côté serveur (filtre, recherche, tri et page appliqués par l'API, compteurs des cartes sur tout
  le parc) : un parc de milliers d'agents n'est plus envoyé d'un bloc au navigateur ; recherche envoyée après une
  courte pause de frappe.
- Kanban chargé colonne par colonne : les 50 tickets les plus récents de chaque colonne, son vrai total et un lien
  vers la liste paginée pour les autres ; auparavant, 500 tickets au plus pour tout le tableau.
- Fiche d'un ticket : les 50 commentaires et les 100 entrées d'historique les plus récents, les plus anciens à la
  demande par paquets (curseur stable, même cloisonnement pour le client) ; le rapport imprimable reste complet. Un
  ticket qui rattache des milliers d'alertes répétées n'est plus envoyé d'un bloc.
- Parc d'agents : la frise d'un agent et la disponibilité du pilotage et du rapport ne lisent plus que la période
  utile (dernier état avant la période et changements de la période), et non tout l'historique, conservé sans limite.

### Sécurité
- Kit Docker : `install.sh` vérifie toujours la signature de l'image publiée, avec cosign s'il est installé, sinon
  avec l'image officielle de cosign épinglée par empreinte ; auparavant, sans cosign, il signalait l'absence de
  vérification et continuait. Exception explicite : `KERYX_VERIFIER_SIGNATURE=non`, pour un registre interne.
- Cloisonnement d'un indexeur Wazuh partagé entre clients (ADR-0031) : deux clients sur le même indexeur avec des
  motifs d'index différents mais qui se recouvrent (`wazuh-alerts-*` et `wazuh-alerts-4.x-*`) étaient acceptés, et
  l'analyste de l'un pouvait voir dans la fiche d'un ticket les événements de l'agent de même numéro de l'autre.
  Chaque client a désormais une source Wazuh (nom de son manager ou de son cluster), exigée et distincte dans ce
  cas, appliquée à chaque recherche et revérifiée sur chaque événement reçu ; un réglage antérieur dans ce cas est
  refusé jusqu'à ce qu'un Admin règle les sources. Relevé par une revue externe ; aucune fuite constatée.

## [0.8.3] : 2026-11-26

### Ajouté
- Fuzzing avec Atheris des entrées non fiables (assainissement HTML, alertes Wazuh), propriétés de sécurité
  vérifiées : 1 minute par cible sur chaque demande de fusion, 10 minutes chaque semaine (`fuzz/`,
  `.github/workflows/fuzzing.yml`) ; les cibles sont rejouées par `tests/test_fuzz.py`.
- OpenSSF Scorecard : évaluation automatique du dépôt à chaque modification de `main` et chaque semaine, badge dans
  le README (`.github/workflows/scorecard.yml`). Badge « ISO/IEC 18974 : conformité déclarée » vers le programme.
- Publication : l'attestation de provenance SLSA de l'archive des sources et de la SBOM est jointe à la version.

### Modifié
- Dépendances de test : pytest borné à 9.0.3 au moins (CVE-2025-71176, relevée par Scorecard ; le verrou installait
  déjà 9.2.0).
- Chaîne d'approvisionnement : actions GitHub épinglées par l'empreinte de leur commit, images de base du
  `Dockerfile` par empreinte, outils Python de la CI et dépendances de test installés avec empreintes
  (`requirements-outils.lock`, `requirements-dev.lock`) et audités par pip-audit ; `tests/test_workflows.py` vérifie
  l'épinglage.

### Corrigé
- Ingestion : une alerte contenant un caractère nul (`\u0000`) échouait sous PostgreSQL (aucun ticket créé) et un
  retour à la ligne dans le nom d'agent coupait le titre. Les caractères de contrôle sont retirés de toute valeur lue
  dans l'alerte ; l'alerte brute conservée reste intacte. Trouvé par le fuzzing. Wazuh, écrit en C, traite a priori les
  journaux comme des chaînes terminées par un caractère nul (non vérifié) ; l'envoi reste possible pour qui détient
  une clé d'API d'ingestion.

## [0.8.2] : 2026-11-25

Même contenu applicatif que la 0.8.1 : cette version termine sa publication.

### Corrigé
- Publication : la version GitHub de la 0.8.1 n'a pas été créée. La commande qui joint les fichiers de la version
  était coupée sur deux lignes dans une valeur YAML qui n'était pas un bloc ; YAML l'a recollée en un nom de fichier
  invalide. L'image `ghcr.io/ozer0x777/keryx:0.8.1` est bien publiée, signée et corrigée, mais la 0.8.1 n'a ni page
  de version, ni SBOM, ni archive des sources, ni liste d'empreintes signée : utiliser la 0.8.2. Un test
  (`tests/test_workflows.py`) refuse désormais cette erreur dans tous les workflows.

## [0.8.1] : 2026-11-25

Publication incomplète (voir 0.8.2) : seule l'image est publiée.

### Ajouté
- Programme de sécurité des composants libres conforme à ISO/IEC 18974 (auto-certification OpenChain) :
  `docs/programme-securite-open-source.md` et registre `docs/registre-vulnerabilites.md` ; veille hebdomadaire des
  vulnérabilités (`veille-vulnerabilites.yml`) avec analyse de l'image par Grype ; la publication est refusée si un
  audit des dépendances échoue ou si l'image contient une vulnérabilité élevée ou critique corrigeable.
- Attestation DCO de chaque commit (`git commit -s`), contrôlée par la CI sur chaque demande de fusion
  (`scripts/verif_dco.py`, job `dco`) ; CONTRIBUTING.md décrit la règle et le choix, l'obtention et le suivi des
  dépendances.
- Publication : l'archive des sources et la liste des empreintes SHA-256 des fichiers de la version (`SHA256SUMS`),
  signée sans clé avec cosign, sont jointes à chaque version ; vérification dans `docs/publication.md`.
- Architecture : acteurs (analyste, manager, client, admin, intégration Wazuh, opérateur, services externes), ce
  que chacun peut faire et ce qui lui est refusé (`docs/architecture.md`, « Acteurs et actions »).
- Gouvernance (`GOVERNANCE.md` : rôles, décisions, continuité), code de conduite (Contributor Covenant 2.1),
  feuille de route (`ROADMAP.md`), vue d'ensemble de l'architecture (`docs/architecture.md`) et argumentaire de
  sécurité (`docs/securite.md` : garanties, modèle de menaces, principes appliqués, cryptographie).
- Couverture des tests mesurée en CI (92 % des instructions), seuil minimal de 85 %.

### Sécurité
- Image Docker : les correctifs de sécurité Debian sont appliqués à la construction (`apt-get upgrade`) ; l'image
  0.8.0 contient des failles élevées déjà corrigées par Debian dans zlib (CVE-2026-85091) et glibc (CVE-2026-19499,
  CVE-2026-5435). pip est retiré de l'image après l'installation des dépendances. Registre : V-2026-002, V-2026-003.

### Corrigé
- Image Docker : le fichier `LICENSE` (MIT) y est désormais copié (`/app/LICENSE`), comme l'exige sa
  redistribution ; la CI le vérifie.
- Accessibilité (WCAG 2.5.3, étiquette dans le nom) : les boutons de mise en forme de l'éditeur affichent « H2 », « B »,
  « I », « 1. » ; leur nom accessible contient désormais ce texte (« Gras, B »), pour la commande vocale. Trouvé par
  axe-core 4.14.
- Parc d'agents : choisir l'agent déjà affiché dans le détail ne recharge plus le panneau (il passait un instant sur
  « Chargement… »).
- README : la limite sur les processus parlait de limites de débit en mémoire ; elles sont partagées en base sous
  PostgreSQL. La vraie limite porte sur les fils de fond.

## [0.8.0] : 2026-11-25

Première version publiée. Les numéros précédents n'ont jamais été publiés : le code portait 0.2.0, le kit Docker et
le dossier d'homologation 0.7.0. La numérotation reprend donc à 0.8.0 pour ne pas paraître antérieure à ces documents.

### Ajouté
- Analyse statique dans la CI, avertissements traités comme des erreurs : ruff pour Python (`ruff.toml`), ESLint pour
  l'interface (`npm run lint`). Les tests échouent sur tout avertissement de dépréciation (`pytest.ini`).
- Politique de sécurité complète (`SECURITY.md`) : délais de réponse et de correction, publication des avis et des
  CVE, crédit des rapporteurs ; résumé en anglais dans `README.md`, `SECURITY.md` et `CONTRIBUTING.md`.
- Parc d'agents Wazuh (ADR-0030) : état, version, disponibilité et historique des agents de chaque client, lus en
  lecture seule dans l'API du manager ; page pour l'équipe et pour le client, export CSV, ticket « agent déconnecté »
  ouvert à la main, parc dans le pilotage et le rapport périodique.
- Image Docker publiée et signée à chaque version (`ghcr.io`), SBOM et attestation de provenance ; le kit Docker
  peut la récupérer au lieu de construire (`KERYX_IMAGE`) et vérifie sa signature si cosign est installé.
- `keryx demo` : client DEMO et dix incidents fictifs, pour essayer sans Wazuh.
- Fiches de prise en main par rôle (`docs/prise-en-main/`).
- Aide au triage (ADR-0028) : titres courts, écart d'horloge entre Wazuh et Keryx signalé, gravité proposée que
  l'analyste retient d'un clic.
- Vues de priorisation de la file : critiques non assignés, en attente du client, dossiers incomplets (ADR-0025).
- Fiche ticket de l'équipe en cinq onglets avec barre fixe (ADR-0026).
- Indicateur et garde-fou de saisies non enregistrées sur la fiche, brouillon de commentaire dans l'onglet (ADR-0024).
- Confirmations nommant le client avant les étapes qui l'engagent, depuis la fiche et le Kanban (ADR-0024).
- `keryx add-user --password-stdin` ; message clair sans terminal.
- Kit Docker : accès par adresse IPv4 (modes `local` et `fourni`).
- CI : audit des dépendances (pip-audit, npm audit), CodeQL, contrôle des secrets et de la rédaction, tests de
  l'interface ; Dependabot ; `SECURITY.md`, `CONTRIBUTING.md`, modèles d'issue et de demande de fusion.

### Corrigé
- Kit Docker : l'image embarquait le client PostgreSQL 17 de Debian alors que le serveur du kit est en version 16 ;
  une sauvegarde PostgreSQL ne pouvait pas être restaurée (`transaction_timeout` refusé par le serveur 16). L'image
  prend désormais le client 16 dans le dépôt officiel de PostgreSQL, et l'erreur de `pg_restore` indique la cause.
- CI : client PostgreSQL 16 pour les tests de sauvegarde, et tests de l'interface lancés d'une façon que Node 22
  comprend.
- Huit traductions anglaises déclarées deux fois (même texte) : doublons retirés.
- Vérification d'un jeton d'horodatage refusé par OpenSSL : le détail d'OpenSSL va au journal du serveur au lieu
  d'être renvoyé à l'utilisateur.
- Recherche VirusTotal : contrôle explicite de l'empreinte juste avant de la placer dans l'URL.
- Caractères de contrôle bidirectionnels écrits en échappements dans le code et les tests (lisibles à la relecture).
- L'identifiant de connexion est lu sans les espaces de début et de fin.
- Libellés restés en français dans l'interface anglaise (pilotage, rapports).

### Modifié
- Clore en faux positif exige un motif de 10 caractères au moins, interne à l'équipe (le client ne le voit pas).
- Un champ de synthèse sans texte visible est enregistré vide.

### Sécurité
- Pillow 12.3.0 vers 13.0.0 : vulnérabilités connues corrigées (relevées par pip-audit).

## État de départ du dépôt : 2026-11-20

Premier commit du dépôt public (code numéroté 0.2.0, non publié). Les changements jusqu'au 22/11 (audit de sécurité,
recherche VirusTotal, contexte Wazuh, kit Docker, README) sont décrits par l'historique git et les ADR 0021 à 0023.

