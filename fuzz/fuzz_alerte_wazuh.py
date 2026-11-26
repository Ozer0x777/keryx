"""Cible de fuzzing : lecture d'une alerte Wazuh, donnée non fiable (keryx/ingest.py, PDIS IV.2.1.w).

Entrée : octets interprétés comme JSON quand c'est possible, sinon comme valeurs aléatoires réparties dans les
champs d'une alerte. Propriétés : seule AlertRejected peut être levée ; le corps du ticket respecte la liste
blanche HTML (fuzz/commun.py) ; le titre est borné et tient sur une ligne ; la classification est bornée ; la date
de détection est toujours une date avec fuseau.
Lancer : python fuzz/fuzz_alerte_wazuh.py -max_total_time=60 (Atheris, voir fuzz/README.md).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz.commun import Defaut, verifier_html  # noqa: E402
from keryx.ids import parse_wazuh_timestamp  # noqa: E402
from keryx.ingest import (  # noqa: E402
    TITLE_MAX, AlertRejected, _classification, _dict, _rule, _sans_controle, _str, build_body, short_title,
)

CHAMPS = ("rule", "agent", "data", "decoder", "timestamp", "location", "id", "full_log")


def _alerte(donnees: bytes):
    """JSON si l'entrée en est ; sinon une alerte dont chaque champ reçoit un morceau de l'entrée."""
    texte = donnees.decode("utf-8", errors="replace")
    try:
        return json.loads(texte)
    except (ValueError, RecursionError):
        pass
    morceaux = texte.split("\x00")
    alerte = {"rule": {"id": morceaux[0][:10], "level": len(morceaux), "description": texte,
                       "groups": morceaux, "pci_dss": morceaux[1:3]}}
    for champ, valeur in zip(CHAMPS[1:], morceaux[1:], strict=False):
        alerte[champ] = {"name": valeur, "id": valeur, "ip": valeur, "srcip": valeur} if champ in ("agent", "data", "decoder") else valeur
    return alerte


def verifier(donnees: bytes) -> None:
    alerte = _alerte(donnees)
    if not isinstance(alerte, dict):
        return  # refusé avant la lecture par le schéma de la route d'ingestion
    alerte = _sans_controle(alerte)  # comme ingest_alert
    try:
        regle = _rule(alerte)
    except AlertRejected:
        return
    corps = build_body(alerte, regle)
    verifier_html(corps)
    if "\x00" in corps:
        raise Defaut("caractère nul dans le corps (refusé par PostgreSQL)")
    agent = _dict(alerte.get("agent"))
    titre = short_title(_str(regle.get("description"), 500), _str(agent.get("name"), 200))
    if any(c < " " or c == "\x7f" for c in titre):
        raise Defaut(f"caractère de contrôle dans le titre : {titre[:80]!r}")
    if len(titre) > TITLE_MAX + 1 + len(" — ") + 200:
        raise Defaut(f"titre trop long : {len(titre)} caractères")
    classes = _classification(regle)
    if len(classes) > 50 * 7 or any(len(c) > 140 or "\x00" in c for c in classes):
        raise Defaut("classification non bornée ou avec caractère nul")
    date = parse_wazuh_timestamp(_str(alerte.get("timestamp"), 40))
    if date.tzinfo is None:
        raise Defaut("date de détection sans fuseau")


if __name__ == "__main__":
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, verifier)
    atheris.Fuzz()
