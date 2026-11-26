"""Cibles de fuzzing (fuzz/) exécutées sans Atheris sur des entrées connues : elles restent justes et importables,
et les entrées qui ont révélé un défaut sont rejouées à chaque CI."""
import importlib.util
from pathlib import Path

import pytest

RACINE = Path(__file__).parents[1]


def _cible(nom):
    spec = importlib.util.spec_from_file_location(nom, RACINE / "fuzz" / f"{nom}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ASSAINISSEMENT = [
    b"", b"<p>texte</p>", b"<script>alert(1)</script>", b'<img src=x onerror="alert(1)">',
    b'<a href="javascript:alert(1)">x</a>', b'<a href=" jav&#x09;ascript:alert(1)">x</a>',
    b'<img src="/api/v1/attachments/00000000-0000-0000-0000-000000000000/content">',
    b"<svg><style>*{}</style></svg>", b"\x00\xff<\x00p>",
]
ALERTES = [
    b"{}", b"[]", b'{"rule": {"id": "1", "level": 3}}',
    b'{"rule": {"id": "5712", "level": 10, "description": "<b>x</b>"}, "agent": {"name": "a\\nb"}}',
    b"~\x00\x00\n",                       # titre sur plusieurs lignes et caractère nul : trouvé par le fuzzing
    b'{"rule": {"id": "1", "level": 12, "description": "a\\u0000b"}, "full_log": "\\u0000"}',
    b'{"rule": {"id": "1", "level": 12, "groups": [[[[[[]]]]]]}, "timestamp": "9999-99-99"}',
]


@pytest.mark.parametrize("entree", ASSAINISSEMENT)
def test_assainissement(entree):
    _cible("fuzz_assainissement").verifier(entree)


@pytest.mark.parametrize("entree", ALERTES)
def test_alerte_wazuh(entree):
    _cible("fuzz_alerte_wazuh").verifier(entree)


def test_la_verification_html_detecte_un_defaut():
    """La vérification elle-même doit refuser un HTML dangereux, sinon le fuzzing ne prouve rien."""
    from fuzz.commun import Defaut, verifier_html
    for dangereux in ('<script>x</script>', '<a href="javascript:x">', '<p onclick="x">', '<img src="/api/v1/me">',
                      '<a href=" java\tscript:x">'):
        with pytest.raises(Defaut):
            verifier_html(dangereux)
