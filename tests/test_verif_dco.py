"""Contrôle DCO des demandes de fusion (scripts/verif_dco.py, OSPS Baseline LE-01.01)."""
import importlib.util
import subprocess
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("verif_dco", Path(__file__).parents[1] / "scripts" / "verif_dco.py")
dco = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dco)


def test_signature_a_l_adresse_de_l_auteur():
    assert dco.signe("Correctif\n\nSigned-off-by: A. Dupont <a@exemple.fr>\n", "A. Dupont", "a@exemple.fr")


def test_signature_au_nom_du_robot():
    msg = "Mise à jour\n\nSigned-off-by: dependabot[bot] <support@github.com>\n"
    assert dco.signe(msg, "dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")


def test_sans_signature_refuse():
    assert not dco.signe("Correctif sans attestation\n", "A. Dupont", "a@exemple.fr")


def test_signature_d_une_autre_personne_refusee():
    assert not dco.signe("Correctif\n\nSigned-off-by: B. Martin <b@exemple.fr>\n", "A. Dupont", "a@exemple.fr")


def test_mention_dans_le_texte_ne_compte_pas():
    assert not dco.signe("Expliquer Signed-off-by: A. Dupont <a@exemple.fr> dans la doc\n", "A. Dupont", "a@exemple.fr")


def test_empreintes_invalides_refusees(capsys):
    assert dco.main(["HEAD~1", "HEAD"]) == 2
    assert dco.main(["a" * 40]) == 2


def _git(depot, *args):
    return subprocess.run(["git", "-C", str(depot), *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def depot(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "A. Dupont")
    _git(tmp_path, "config", "user.email", "a@exemple.fr")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "Base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_demande_dont_chaque_commit_est_signe(depot):
    base = _git(depot, "rev-parse", "HEAD")
    _git(depot, "commit", "-q", "-s", "--allow-empty", "-m", "Premier")
    _git(depot, "commit", "-q", "-s", "--allow-empty", "-m", "Second")
    assert dco.main([base, _git(depot, "rev-parse", "HEAD")]) == 0


def test_demande_avec_un_commit_non_signe(depot, capsys):
    base = _git(depot, "rev-parse", "HEAD")
    _git(depot, "commit", "-q", "-s", "--allow-empty", "-m", "Signé")
    _git(depot, "commit", "-q", "--allow-empty", "-m", "Oublié")
    assert dco.main([base, _git(depot, "rev-parse", "HEAD")]) == 1
    assert "Oublié" in capsys.readouterr().out
