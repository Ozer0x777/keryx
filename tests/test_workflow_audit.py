"""Qualification, cycle ISO 27035, MITRE manuel, IODEF, audit chaîné."""
from sqlalchemy import select

from keryx import audit
from keryx.models import AuditEntry, TicketEvent
from keryx.severity import criticite_initiale, gravite

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login


def test_bareme_criticite():
    assert criticite_initiale(6) is None
    assert [criticite_initiale(n) for n in (7, 9, 10, 11, 12, 13, 14, 16)] == [
        "Faible", "Faible", "Moyenne", "Moyenne", "Élevée", "Élevée", "Critique", "Critique"]


def test_grille_gravite():
    assert gravite("limites", "standard") == "Faible"
    assert gravite("significatifs", "sensible") == "Élevée"
    assert gravite("graves", "vital") == "Critique"


def test_qualification_obligatoire_avant_reponse(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"}).status_code == 200
    r = a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_reponse"})
    assert r.status_code == 409  # pas encore qualifié
    q = a.post("/api/v1/tickets/ACME-1/qualification",
               json={"verdict": "vrai_positif_avere", "dommages": "significatifs", "impact": "poste isolé"})
    assert q.json()["gravite"] == "Élevée" and q.json()["rex_required"] is True
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_reponse"}).status_code == 200
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "cloture"}).status_code == 200
    assert a.get("/api/v1/tickets?rex_en_attente=true").json()["items"][0]["ref"] == "ACME-1"
    # Le REX doit être rédigé avant de clore l'étape
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "retour_experience"}).status_code == 409
    a.put("/api/v1/tickets/ACME-1/synthese", json={"rex_html": "<p>Durcir l'accès SSH.</p>"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "retour_experience"}).status_code == 200


def test_faux_positif(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif"}).status_code == 409
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif"}).status_code == 200


def test_transition_interdite(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "cloture"}).status_code == 409


def test_mitre_manuel_trace(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/tickets/ACME-1/mitre", json={"techniques": ["pas-un-id"]}).status_code == 422
    r = a.post("/api/v1/tickets/ACME-1/mitre", json={"techniques": ["T1110.001"]})
    assert r.json()["mitre_source"] == "manuel"
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "mitre_manuel")).one()
    assert ev.details == {"avant": ["T1110"], "apres": ["T1110.001"]}


def test_export_iodef(app, db, world, alert):
    ingest(app, world["keys"]["DELTA"], alert(ALERT_CRITICAL))
    a = login(app, db, "analyst_delta")
    doc = a.get("/api/v1/tickets/DELTA-1/iodef").json()
    inc = doc["Incident"][0]
    assert inc["IncidentID"]["id"] == "DELTA-1" and inc["DetectTime"].endswith("Z")
    assert inc["Method"][0]["Reference"][0]["ReferenceName"]["ID"] == "T1048"


def test_journal_audit_chaine_et_infalsifiable(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.get("/api/v1/tickets/ACME-1")
    actions = [e.action for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq))]
    assert "ticket.create" in actions and "auth.login_success" in actions and "ticket.read" in actions
    assert audit.verify_chain(db) == (True, None)
    adm = login(app, db, "admin")
    assert adm.get("/api/v1/audit/verify").json()["chain_ok"] is True
    # Falsification d'une entrée → chaîne rompue
    e = db.scalars(select(AuditEntry).where(AuditEntry.action == "ticket.read")).first()
    e.actor = "quelqu'un d'autre"
    db.commit()
    ok, bad = audit.verify_chain(db)
    assert ok is False and bad == e.seq


def test_format_syslog_rfc5424(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    e = db.scalars(select(AuditEntry).order_by(AuditEntry.seq)).first()
    line = audit.to_syslog(e, "keryx-test")
    assert line.startswith("<110>1 ") and " keryx-test keryx - AUDIT [keryx@32473 " in line
