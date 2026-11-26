# Contribuer à Keryx

*In English: issues, pull requests and comments in English are welcome; see the summary at the end.*

Keryx est un projet libre (licence MIT). Les contributions sont bienvenues : correctifs, tests, traductions,
documentation.

## Avant de commencer

- Une vulnérabilité ne se signale pas en issue publique : voir `SECURITY.md`.
- Pour une nouvelle fonction, ouvrir d'abord une issue pour en discuter : Keryx suit des référentiels (PDIS, PRIS,
  ISO/IEC 27035) et chaque fonction doit pouvoir être rattachée à une exigence.

## Règles du projet

1. **Une exigence lue, citée.** Une fonction liée à un référentiel cite l'exigence précise (ex. PDIS IV.3.8.g) et
   seulement après avoir lu le texte. Une exigence non vérifiée est écrite « à vérifier », jamais devinée.
2. **Un ADR par choix technique** dans `docs/adr/` (numéro suivant, format des ADR existants : statut, décision,
   exigences, conséquences, tests). La matrice `docs/matrice-tracabilite.md` est mise à jour.
3. **Cloisonnement par client testé.** Toute route qui lit ou écrit des données d'un ticket a un test prouvant qu'un
   utilisateur d'un autre client ne les atteint pas, et que le rôle Admin ne lit pas le contenu des tickets.
4. **Tout est tracé.** Une action qui modifie un ticket, un compte ou un réglage écrit au journal d'audit.
5. **Pas de devinette métier.** Keryx ne déduit pas une technique MITRE ATT&CK, une gravité ou un verdict sans
   règle explicite validée par l'équipe.
6. **Rédaction.** Documentation et messages de commit en français. Pas de tiret cadratin dans les fichiers Markdown
   (le contrôle `scripts/verif_depot.py` le refuse). Toute chaîne d'interface passe par `t()` / `tr()` et a sa
   traduction anglaise dans `web/src/i18n.en.js`.

## Règles de code

- **Python** : PEP 8, lignes de 120 caractères au plus ; règles de `ruff.toml` (pyflakes, pièges courants de
  bugbear, erreurs pylint), appliquées en CI. Les exceptions sont déclarées dans `ruff.toml` avec leur raison.
- **Interface** : règles recommandées d'ESLint et des hooks React (`web/eslint.config.js`), appliquées en CI sans
  aucun avertissement toléré.
- **Nommage** : noms de domaine en français, comme dans le code existant (`gravite`, `criticite_initiale`) ;
  identifiants techniques en anglais quand ils suivent une bibliothèque.
- **Sécurité** : aucun secret dans le code ; aucune donnée non fiable dans du HTML sans assainissement ; aucune
  redirection suivie ni certificat ignoré par défaut dans un connecteur (voir `docs/securite.md`).

## Vérifier avant de proposer

```bash
python -m pytest -q --cov=keryx             # tests (SQLite) et couverture (85 % au moins en CI)
python scripts/pg_tests.py                  # mêmes tests sous PostgreSQL (paquet pgserver)
cd web && npm run build && npm test         # interface
cd e2e && node run.mjs                      # parcours dans un navigateur (CHROME_PATH si besoin)
ruff check .                                # analyse statique Python (règles : ruff.toml)
cd web && npm run lint                      # analyse statique de l'interface (ESLint)
python3 scripts/verif_depot.py              # aucun secret, aucun tiret cadratin en Markdown
```

Les tests échouent sur tout avertissement de dépréciation (`pytest.ini`), et l'analyse statique sur tout
avertissement : on corrige, ou on justifie l'exception en commentaire à l'endroit où on la déclare.

La CI relance tout cela sur chaque demande de fusion, avec l'audit des dépendances et CodeQL.

## Demande de fusion

Remplir le modèle proposé : ce qui change, l'exigence citée, l'ADR, les tests ajoutés, l'effet sur le cloisonnement
et sur l'audit. Une demande sans test pour un changement de comportement ne sera pas fusionnée.

## Attester chaque commit (DCO)

Chaque commit porte la ligne `Signed-off-by: Nom <adresse>` de son auteur, ajoutée par `git commit -s`. Par cette
ligne, l'auteur atteste le [Developer Certificate of Origin 1.1](https://developercertificate.org/) : il a le droit
de proposer cette contribution sous la licence du projet (MIT), parce qu'il l'a écrite ou qu'elle provient d'une
source compatible, et il accepte qu'elle soit publiée avec son nom. Le nom et l'adresse sont ceux de l'auteur du
commit (une adresse `noreply` de GitHub convient).

La CI refuse une demande de fusion dont un commit n'a pas cette ligne (job `dco`, `scripts/verif_dco.py`). Pour
rattraper des commits déjà faits : `git rebase --signoff main`, puis pousser à nouveau la branche. Sur le site
GitHub, la ligne est ajoutée d'office aux commits faits dans l'interface web. Une attestation n'est pas une
signature cryptographique : celle-ci n'est pas exigée.

## Dépendances

- **Choix.** Une nouvelle dépendance se justifie dans la demande de fusion : bibliothèque libre sous licence
  compatible avec MIT, maintenue (versions et correctifs de sécurité récents), reconnue pour son usage (la
  cryptographie passe par `cryptography`, `argon2-cffi` et le module `secrets`, jamais par du code maison). Pas de
  dépendance pour quelques lignes que le projet peut écrire et tester lui-même.
- **Obtention.** Python : dépendances directes et leurs bornes dans `requirements.txt`, figées avec leurs empreintes
  dans `requirements.lock` (`uv pip compile requirements.txt --generate-hashes --python-version 3.12
  --python-platform linux -o requirements.lock`), installées depuis PyPI par `pip install --require-hashes -r
  requirements.lock`. Interface et parcours : registre npm, versions figées dans `package-lock.json`, installées par
  `npm ci`. Outils de la CI (pip-audit, ruff) et dépendances de test : `requirements-outils.lock` et
  `requirements-dev.lock`, eux aussi installés avec `--require-hashes` (régénérer avec `uv pip compile
  requirements-outils.txt --generate-hashes --python-version 3.12 --python-platform linux -o requirements-outils.lock`
  et `uv pip compile requirements-dev.txt -c requirements.lock --generate-hashes --python-version 3.12
  --python-platform linux -o requirements-dev.lock` ; de même pour `requirements-fuzz.txt`, le fuzzer Atheris). Conteneurs : images officielles `python` et `node`, épinglées
  par empreinte (`@sha256:`). CI : actions GitHub épinglées par l'empreinte de leur commit, version en commentaire
  (`tests/test_workflows.py` le vérifie). Aucune dépendance n'est copiée dans le dépôt.
- **Suivi.** Dependabot propose chaque semaine les mises à jour npm, actions GitHub et Docker (empreintes comprises),
  et signale les vulnérabilités des dépendances Python ; `pip-audit` (sur les trois verrous Python) et `npm audit`
  bloquent la CI sur une vulnérabilité connue ; OpenSSF Scorecard évalue le dépôt chaque semaine ;
  une SBOM CycloneDX accompagne chaque version (`docs/publication.md`). Le tout forme le programme de sécurité des
  composants libres (`docs/programme-securite-open-source.md`, ISO/IEC 18974) : le lire avant d'ajouter ou de
  mettre à jour une dépendance.

## Gouvernance et conduite

Qui décide et comment : `GOVERNANCE.md`. Comportement attendu : `CODE_OF_CONDUCT.md`. Ce qui est prévu :
`ROADMAP.md`.

## Relecture

Keryx a pour l'instant un seul mainteneur. Il relit chaque demande de fusion avant de la fusionner ; la CI doit être
verte. Réponse visée sous 14 jours ; une demande restée sans réponse peut être relancée en commentaire. Chaque
commit porte l'attestation DCO (voir plus haut) ; la signature cryptographique des commits n'est pas exigée.

## Ajouter des tests

Toute nouvelle fonction et toute correction de bogue arrivent avec leurs tests automatisés : test pytest pour le
serveur (`tests/`), test `node --test` pour la logique de l'interface (`web/tests/`), scénario de navigateur pour un
parcours (`e2e/scenarios/`). Un correctif de sécurité arrive avec le test qui prouve que la faille est fermée.

## In English

Keryx is a free software (MIT) incident console for Wazuh-based SOCs. Its documentation is in French, but issues,
pull requests and comments in English are welcome. Before opening a pull request, run the checks listed above (tests,
`ruff check .`, `npm run lint`, `scripts/verif_depot.py`); every behaviour change comes with automated tests. Every
commit must carry a Developer Certificate of Origin sign-off (`git commit -s`), checked by CI. Report
vulnerabilities privately, as described in `SECURITY.md`.
