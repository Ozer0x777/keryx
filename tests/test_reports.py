"""Pilotage et rapports (v0.6). [PDIS IV.2.1.bb ; RFC 7970 / 8727]"""
import csv
import io
from datetime import timedelta

from sqlalchemy import select

from keryx.ids import utcnow
from keryx.iodef import validate
from keryx.models import Ticket

from .conftest import ALERT_CRITICAL, ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login


def seed(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    ingest(app, world["keys"]["DELTA"], alert(ALERT_NO_MITRE))


def test_tableau_de_bord_cloisonne_et_chiffres(app, db, world, alert):
    seed(app, db, world, alert)
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/assign", json={"username": "analyst_acme"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    d = a.get("/api/v1/dashboard").json()
    assert d["clients"] == ["ACME"]                      # l'analyste ne voit pas DELTA
    assert d["totals"]["created"] == 2 and d["totals"]["closed"] == 1 and d["totals"]["open"] == 1
    assert d["open_by_severity"]["Critique"] == 1
    assert d["delays"]["qualified_count"] == 1 and d["delays"]["resolution_hours_avg"] is not None
    assert d["sla"]["rate_percent"] == 100
    assert sum(x["created"] for x in d["trend"]) == 2 and len(d["trend"]) == 30
    m = login(app, db, "manager")
    assert sorted(m.get("/api/v1/dashboard").json()["clients"]) == ["ACME", "DELTA"]
    assert m.get("/api/v1/dashboard", params={"client": "DELTA"}).json()["totals"]["created"] == 1
    assert a.get("/api/v1/dashboard", params={"client": "DELTA"}).status_code == 404


def test_tableau_de_bord_refuse_admin_client_et_periode_excessive(app, db, world, alert):
    assert login(app, db, "admin").get("/api/v1/dashboard").status_code == 403
    assert login(app, db, "client_acme").get("/api/v1/dashboard").status_code == 403
    m = login(app, db, "manager")
    assert m.get("/api/v1/dashboard", params={"from": "2020-01-01", "to": "2026-01-01"}).status_code == 422
    assert m.get("/api/v1/dashboard", params={"from": "2026-02-01", "to": "2026-01-01"}).status_code == 422


def test_depassement_sla_compte_dans_la_charge(app, db, world, alert):
    seed(app, db, world, alert)
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-2/assign", json={"username": "analyst_acme"})
    row = db.scalars(select(Ticket).where(Ticket.ref == "ACME-2")).one()
    row.created_at = utcnow() - timedelta(hours=5)
    db.commit()
    d = a.get("/api/v1/dashboard").json()
    mine = next(w for w in d["workload"] if w["name"] == "analyst_acme")
    assert mine["open"] == 1 and mine["overdue"] == 1 and d["totals"]["overdue"] == 1


def test_registre_json_csv_et_injection(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    evil = alert(ALERT_NO_MITRE)
    evil["rule"]["description"] = "=HYPERLINK(\"http://x\",\"clic\")"
    ingest(app, world["keys"]["ACME"], evil)
    a = login(app, db, "analyst_acme")
    r = a.get("/api/v1/registre", params={"client": "ACME", "format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][0] == "reference" and len(rows) == 3
    assert any(c.startswith("'=HYPERLINK") for row in rows for c in row)    # formule neutralisée
    assert not any(c.startswith("=") for row in rows for c in row)
    assert a.get("/api/v1/registre", params={"client": "DELTA"}).status_code == 404
    assert a.get("/api/v1/registre", params={"client": "ACME", "format": "xml"}).status_code == 422
    assert len(a.get("/api/v1/registre", params={"client": "ACME"}).json()["items"]) == 2
    assert login(app, db, "client_acme").get("/api/v1/registre", params={"client": "ACME"}).status_code == 403


def test_rapport_periodique(app, db, world, alert):
    seed(app, db, world, alert)
    m = login(app, db, "manager")
    assert m.get("/api/v1/reports/period").status_code == 422
    r = m.get("/api/v1/reports/period", params={"client": "ACME"}).json()
    assert r["client"]["key"] == "ACME" and [i["ref"] for i in r["incidents"]] == ["ACME-1", "ACME-2"]
    assert login(app, db, "analyst_acme").get("/api/v1/reports/period", params={"client": "DELTA"}).status_code == 404


def test_export_iodef_conforme_et_validateur(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    doc = a.get("/api/v1/tickets/ACME-1/iodef").json()
    assert validate(doc) == []
    broken = {"version": "2.0", "Incident": [{"purpose": "x", "IncidentID": {"id": "A"}, "GenerationTime": "hier"}]}
    errors = validate(broken)
    assert any("purpose" in e for e in errors) and any("IncidentID" in e for e in errors)
    assert any("GenerationTime" in e for e in errors) and any("Contact" in e for e in errors)
    assert validate({"version": "1.0", "Incident": []})
