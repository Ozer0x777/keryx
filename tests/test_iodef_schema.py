"""Export IODEF validé contre le schéma JSON officiel de la RFC 8727 (annexe B, figure 6). [RFC 7970, RFC 8727]"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login

SCHEMA = json.loads((Path(__file__).parent / "data" / "iodef" / "iodef-2.0-rfc8727.schema.json").read_text())


def erreurs(doc: dict) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path))} : {e.message}" for e in Draft4Validator(SCHEMA).iter_errors(doc)]


def test_schema_officiel_lisible():
    """La figure 6 de la RFC 8727 contient des « required » vides (IndicatorExpression, Reference), que le métaschéma
    draft-04 refuse (au moins un élément). C'est son seul écart au métaschéma ; la validation des documents n'en dépend
    pas (une liste vide n'exige rien)."""
    ecarts = list(Draft4Validator(Draft4Validator.META_SCHEMA).iter_errors(SCHEMA))
    assert ecarts and all(e.validator == "minItems" and e.instance == [] and e.path[-1] == "required" for e in ecarts)


@pytest.mark.parametrize("qualifie", [False, True])
def test_export_iodef_valide_contre_le_schema_officiel(app, db, world, alert, qualifie):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    a = login(app, db, "analyst_acme")
    if qualifie:
        # Ticket rempli : qualification, MITRE, commentaire visible, synthèse ; l'export grossit, il doit rester valide.
        a.put(f"/api/v1/tickets/{ref}/qualification", json={"dommages": "Importants", "importance": "Importante",
                                                              "verdict": "vrai_positif", "tlp": "TLP:AMBER"})
        a.post(f"/api/v1/tickets/{ref}/mitre", json={"id": "T1110"})
        a.post(f"/api/v1/tickets/{ref}/comments", json={"body_html": "<p>Analyse en cours.</p>", "visible_client": True})
        a.post(f"/api/v1/tickets/{ref}/status", json={"status": "en_evaluation"})
    doc = a.get(f"/api/v1/tickets/{ref}/iodef").json()
    e = erreurs(doc)
    assert not e, "\n".join(e)


def test_le_schema_refuse_un_export_casse():
    """Le schéma officiel attrape bien ce qu'il doit attraper (le test ci-dessus n'est pas vide de sens)."""
    assert erreurs({"version": "2.0", "Incident": []})                                  # au moins un incident
    assert erreurs({"version": "2.0", "Incident": [{"purpose": "inconnu"}]})          # membres obligatoires, énumération
    assert erreurs({"version": "2.0", "Incident": [{}], "Inconnu": 1})                  # aucun membre en plus
