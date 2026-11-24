# Contribuer à Keryx

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

## Vérifier avant de proposer

```bash
python -m pytest -q                         # tests (SQLite)
python scripts/pg_tests.py                  # mêmes tests sous PostgreSQL (paquet pgserver)
cd web && npm run build && npm test         # interface
cd e2e && node run.mjs                      # parcours dans un navigateur (CHROME_PATH si besoin)
python3 scripts/verif_depot.py              # aucun secret, aucun tiret cadratin en Markdown
```

La CI relance tout cela sur chaque demande de fusion, avec l'audit des dépendances et CodeQL.

## Demande de fusion

Remplir le modèle proposé : ce qui change, l'exigence citée, l'ADR, les tests ajoutés, l'effet sur le cloisonnement
et sur l'audit. Une demande sans test pour un changement de comportement ne sera pas fusionnée.

> À COMPLÉTER PAR LE MAINTENEUR : règles de relecture (nombre de relecteurs, délai), signature des commits si exigée.
