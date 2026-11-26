# Fuzzing

Cibles Atheris (fuzzer guidé par la couverture, Google) sur le code qui reçoit des données non fiables. Chaque cible
vérifie des propriétés de sécurité, pas seulement l'absence de plantage.

| Cible | Code visé | Propriétés vérifiées |
|---|---|---|
| `fuzz_assainissement.py` | `keryx/sanitize.py` (`clean_html`) | Aucune exception ; sortie limitée à la liste blanche de balises et d'attributs, sans gestionnaire d'événement, sans adresse hors `https:`, `mailto:` ou relative, sans image hors des pièces déposées (`commun.py`) |
| `fuzz_alerte_wazuh.py` | `keryx/ingest.py` (lecture d'une alerte) | Seule `AlertRejected` peut être levée ; corps HTML conforme à la liste blanche et sans caractère nul ; titre borné, sans caractère de contrôle ; classification bornée ; date de détection avec fuseau |

## Lancer

```bash
pip install --require-hashes -r requirements.lock && pip install --require-hashes -r requirements-fuzz.lock
mkdir -p corpus && python fuzz/fuzz_alerte_wazuh.py corpus -max_total_time=120
```

En CI (`.github/workflows/fuzzing.yml`) : 1 minute par cible sur chaque demande de fusion, 10 minutes chaque semaine.
`tests/test_fuzz.py` rejoue les cibles sans Atheris sur des entrées connues, dont celles qui ont révélé un défaut.

## Défaut trouvé

Un défaut trouvé est corrigé dans une demande de fusion avec un test qui rejoue l'entrée, et noté ici.

| Date | Cible | Défaut | Correctif |
|---|---|---|---|
| 26/11/2026 | `fuzz_alerte_wazuh` | Un caractère nul (`\u0000`) dans un champ de l'alerte faisait échouer l'ingestion sous PostgreSQL (« text fields cannot contain NUL »), donc aucun ticket ; un retour à la ligne dans le nom d'agent coupait le titre | Caractères de contrôle retirés de toute valeur lue dans l'alerte, l'alerte brute gardée intacte (`keryx/ingest.py`, test `test_caracteres_de_controle_de_l_alerte`) |
