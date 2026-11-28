"""Classification ETSI GS ISI 002 et export IODEF 2.0. [PDIS IV.2.1.y ; ETSI GS ISI 002 §4.4, Annexe B, §7.4]"""
import pytest

from keryx import isi
from keryx.iodef import validate

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login

GOOD = {"category": "IEX", "who_why": "malicious_act", "what": "unauthorized_access", "how": "unauthorized_access",
        "status": "underway", "vulnerability": ["configuration", "behavioural"], "asset": "systems", "cia": "confidentiality",
        "impact": "direct", "detail": {"who_why": "External agent: Organized crime group", "asset": "Perimeter system"}}


def test_dictionnaire_conforme_a_l_annexe_b():
    assert [v[0] for v in isi.AXES["what"].values()] == [f"B.1.2.{i}" for i in range(1, 12)]     # 11 catégories « quoi »
    assert [v[0] for v in isi.AXES["status"].values()] == ["B.1.4.1", "B.1.4.2", "B.1.4.3"]
    assert len(isi.AXES["vulnerability"]) == 6 and len(isi.AXES["asset"]) == 7 and len(isi.AXES["cia"]) == 3
    assert isi.MANDATORY == ("who_why", "what", "status", "asset")                                # clause 4.4


def test_validation():
    assert isi.clean(GOOD)["vulnerability"] == ["configuration", "behavioural"]
    for bad, msg in [({"what": "inconnu"}, "inconnue"), ({"status": ["underway", "failed"]}, "Un seul"),
                     ({"vulnerability": ["software", "configuration", "material", "conception"]}, "au plus 3"),
                     ({"category": "XYZ"}, "Catégorie"), ({"how": "x"}, "how"), ({"detail": {"axe": "x"}}, "inconnu"),
                     ({"detail": "pas un objet"}, "objet")]:
        with pytest.raises(isi.IsiError, match=msg):
            isi.clean(bad)
    assert isi.clean({"detail": {"what": "x" * 500}})["detail"]["what"] == "x" * isi.DETAIL_MAX     # précision bornée
    assert isi.missing({"what": "breakdown"}) == ["who_why", "status", "asset"]


def test_classification_droits_cloisonnement_et_export(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    d = a.get("/api/v1/isi/dictionary").json()
    assert d["mandatory"] == ["who_why", "what", "status", "asset"] and len(d["how"]) == 11 and d["how"][0]["ref"] == "B.1.3.1"
    assert a.get("/api/v1/tickets/ACME-1/isi").json()["missing"] == ["who_why", "what", "status", "asset"]
    assert a.get("/api/v1/tickets/ACME-1/isi/iodef").status_code == 409                          # incomplète : refus explicite
    assert a.put("/api/v1/tickets/ACME-1/isi", json={"what": "nimporte"}).status_code == 422
    r = a.put("/api/v1/tickets/ACME-1/isi", json=GOOD)
    assert r.status_code == 200 and r.json()["missing"] == []
    doc = a.get("/api/v1/tickets/ACME-1/isi/iodef").json()
    assert validate(doc) == [] and doc["version"] == "2.00" and doc["format-id"] == "ETSI ISI"
    from .test_iodef_schema import erreurs
    assert erreurs(doc) == []                                     # schéma officiel de la RFC 8727
    inc = doc["Incident"][0]
    assert inc["purpose"] == "reporting" and inc["restriction"] == "private" and inc["IncidentID"] == {"id": "ACME-1", "name": "keryx"}
    assert inc["ReportTime"] and inc["GenerationTime"] and inc["DetectTime"]
    byaxis = {(x["meaning"], x["formatid"] if "formatid" in x else None): x["value"] for x in inc["AdditionalData"]}
    assert byaxis[("ETSI-ISI:what", "B.1.2.1")].startswith("Unauthorized access to a system")
    assert byaxis[("ETSI-ISI:how", "B.1.3.1")] and byaxis[("ETSI-ISI:status", "B.1.4.1")].startswith("Security event attempt")
    assert "Organized crime group" in byaxis[("ETSI-ISI:who_why", "B.1.1.4")]
    assert {k[1] for k in byaxis if k[0] == "ETSI-ISI:vulnerability"} == {"B.1.5.3", "B.1.5.1"}
    # Traçabilité : l'ancienne et la nouvelle valeur sont dans le registre des actions
    assert any(e["action"] == "classification_isi" for e in a.get("/api/v1/tickets/ACME-1").json()["events"])
    assert a.get("/api/v1/tickets/ACME-1").json()["isi"]["what"] == "unauthorized_access"
    # Cloisonnement, rôles : client et autre client n'y accèdent pas ; le client ne voit jamais la classification
    assert a.get("/api/v1/tickets/DELTA-1/isi").status_code == 404
    assert a.put("/api/v1/tickets/DELTA-1/isi", json=GOOD).status_code == 404
    c = login(app, db, "client_acme")
    assert c.get("/api/v1/tickets/ACME-1/isi").status_code == 403 and c.get("/api/v1/tickets/ACME-1").json()["isi"] is None
    assert login(app, db, "admin").get("/api/v1/isi/dictionary").status_code == 403


def test_classification_refusee_sur_ticket_clos(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    assert a.put("/api/v1/tickets/ACME-1/isi", json=GOOD).status_code == 409
