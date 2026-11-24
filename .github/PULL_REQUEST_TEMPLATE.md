## Ce qui change

## Exigence citée

<!-- ex. PDIS IV.3.8.g ; texte lu. « Aucune » pour un correctif sans lien avec un référentiel. -->

## Vérifications

- [ ] Tests ajoutés ou mis à jour (`python -m pytest -q`, `npm test`, scénario e2e si l'interface change)
- [ ] Cloisonnement par client : un autre client ne voit rien de nouveau ; l'Admin ne lit pas le contenu des tickets
- [ ] Toute action nouvelle est inscrite au journal d'audit
- [ ] ADR ajouté pour un choix technique, matrice de traçabilité à jour
- [ ] Chaînes d'interface traduites (`web/src/i18n.en.js`)
- [ ] `python3 scripts/verif_depot.py` passe
- [ ] Entrée dans `CHANGELOG.md` (section « Non publié »)
