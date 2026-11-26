"""Cible de fuzzing : assainissement du HTML des tickets (keryx/sanitize.py, ASVS V1, XSS stocké).

Entrée : texte arbitraire (HTML hostile, encodages, caractères de contrôle). Propriétés : clean_html ne lève
jamais d'exception et sa sortie respecte la liste blanche (fuzz/commun.py).
Lancer : python fuzz/fuzz_assainissement.py -max_total_time=60 (Atheris, voir fuzz/README.md).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz.commun import verifier_html  # noqa: E402
from keryx.sanitize import clean_html  # noqa: E402


def verifier(donnees: bytes) -> None:
    texte = donnees.decode("utf-8", errors="replace")
    verifier_html(clean_html(texte))


if __name__ == "__main__":
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, verifier)
    atheris.Fuzz()
