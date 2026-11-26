"""Workflows GitHub Actions : erreurs de syntaxe qui ne se voient qu'à l'exécution (la publication ne tourne qu'à
l'étiquette d'une version). Origine : la version GitHub de la 0.8.1 n'a pas été créée, une commande coupée par « \\ »
dans une valeur YAML sur une seule ligne était recollée en « \\  » et passait un nom de fichier invalide."""
import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = sorted((Path(__file__).parents[1] / ".github" / "workflows").glob("*.yml"))


def _etapes():
    for chemin in WORKFLOWS:
        for nom, job in yaml.safe_load(chemin.read_text())["jobs"].items():
            for i, etape in enumerate(job.get("steps", [])):
                yield f"{chemin.name}:{nom}:{etape.get('name', i)}", etape


def test_workflows_presents():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "codeql.yml", "fuzzing.yml", "publication.yml", "scorecard.yml", "veille-vulnerabilites.yml"}


@pytest.mark.parametrize("ident,etape", list(_etapes()), ids=lambda v: v if isinstance(v, str) else "")
def test_pas_de_ligne_coupee_recollee(ident, etape):
    """Une commande coupée par « \\ » doit être dans un bloc « run: | » : sinon YAML recolle les lignes en « \\  »."""
    script = etape.get("run") or ""
    assert "\\ " not in script.replace("\\ \n", ""), f"{ident} : « \\ » suivi d'une espace (ligne recollée par YAML)"


def test_publication_joint_les_fichiers_de_la_version():
    etapes = dict(_etapes())
    script = etapes["publication.yml:publier:Créer la version GitHub"]["run"]
    for fichier in ("sbom.cdx.json", "-sources.tar.gz", "SHA256SUMS", "SHA256SUMS.sigstore.json"):
        assert fichier in script


@pytest.mark.parametrize("ident,etape", [(i, e) for i, e in _etapes() if "uses" in e], ids=lambda v: v if isinstance(v, str) else "")
def test_actions_epinglees_par_empreinte(ident, etape):
    """Chaque action tierce est épinglée par l'empreinte de son commit (une étiquette peut être déplacée) ; la
    version lisible suit en commentaire, et Dependabot met les deux à jour."""
    assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", etape["uses"]), f"{ident} : {etape['uses']}"


def test_outils_python_installes_avec_empreintes():
    for chemin in WORKFLOWS:
        for ligne in chemin.read_text().splitlines():
            if "pip install" in ligne:
                assert "--require-hashes" in ligne, f"{chemin.name} : {ligne.strip()}"
