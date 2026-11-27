"""Délai d'acquittement (ADR-0032, partie 1) : première action humaine de l'équipe sur un ticket, bouton « Je prends »,
moyenne et 90e centile par criticité dans le pilotage, présence dans le rapport client au choix du manager."""
from datetime import timedelta

from sqlalchemy import select

from keryx.models import AuditEntry, Ticket, TicketEvent
from keryx.routes_reports import _p90

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login


def _t(db, ref):
    db.rollback()
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.ref == ref)).one()


def test_consulter_commenter_n_acquittent_pas_je_prends_oui(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    a = login(app, db, "analyst_acme")
    fiche = a.get(f"/api/v1/tickets/{ref}").json()
    assert fiche["acquitted_at"] is None and fiche["acquittement_s"] is None
    assert a.post(f"/api/v1/tickets/{ref}/comments", json={"body_html": "<p>Je regarde</p>"}).status_code in (200, 201)
    assert _t(db, ref).acquitted_at is None
    r = a.post(f"/api/v1/tickets/{ref}/prise-en-charge")
    assert r.status_code == 200 and r.json()["assignee_username"] == "analyst_acme"
    t = _t(db, ref)
    assert t.acquitted_by == "analyst_acme" and t.assignee_id is not None
    premier = t.acquitted_at
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "prise_en_charge")).one()
    assert ev.details == {"assignee": "analyst_acme", "avant": None} and not ev.visible_client
    # une action suivante ne déplace pas l'acquittement ; reprendre un ticket déjà à soi ne crée pas d'événement
    m = login(app, db, "manager")
    assert m.post(f"/api/v1/tickets/{ref}/prise-en-charge").status_code == 200
    assert m.post(f"/api/v1/tickets/{ref}/prise-en-charge").status_code == 200
    t = _t(db, ref)
    assert t.acquitted_at == premier and t.acquitted_by == "analyst_acme"
    assert len(db.scalars(select(TicketEvent).where(TicketEvent.action == "prise_en_charge")).all()) == 2
    fiche = a.get(f"/api/v1/tickets/{ref}").json()
    assert fiche["acquitted_by"] == "analyst_acme" and isinstance(fiche["acquittement_s"], int)
    assert "acquitted_at" not in login(app, db, "client_acme").get(f"/api/v1/tickets/{ref}").json()


def test_qualification_et_statut_acquittent(app, db, world, alert):
    r1 = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    r2 = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    a = login(app, db, "analyst_acme")
    assert a.post(f"/api/v1/tickets/{r1}/qualification", json={"tlp": "TLP:RED"}).status_code == 200
    assert a.post(f"/api/v1/tickets/{r2}/status", json={"status": "en_evaluation"}).status_code == 200
    assert _t(db, r1).acquitted_by == "analyst_acme" and _t(db, r2).acquitted_by == "analyst_acme"


def test_je_prends_droits(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    assert login(app, db, "client_acme").post(f"/api/v1/tickets/{ref}/prise-en-charge").status_code == 403
    assert login(app, db, "admin").post(f"/api/v1/tickets/{ref}/prise-en-charge").status_code == 403
    assert _t(db, ref).acquitted_at is None


def test_p90():
    assert _p90([]) is None
    assert _p90([5.0]) == 5.0
    assert _p90([float(x) for x in range(1, 11)]) == 9.0
    assert _p90([float(x) for x in range(1, 21)]) == 18.0


def test_pilotage_et_rapport_client(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    t = _t(db, ref)
    crit = t.criticite_initiale
    t.acquitted_at, t.acquitted_by = t.detected_at + timedelta(minutes=12), "analyst_acme"
    db.commit()
    m = login(app, db, "manager")
    d = m.get("/api/v1/dashboard", params={"client": "ACME"}).json()["acquittement"][crit]
    assert d == {"moyenne_min": 12.0, "p90_min": 12.0, "acquittes": 1, "non_acquittes": 0, "horloge_en_avance": 0}
    # rapport client : absent par défaut, présent quand le manager l'active ; le plancher TLP n'est pas touché
    r = m.get("/api/v1/reports/period", params={"client": "ACME"}).json()
    assert r["acquittement_inclus"] is False and "acquittement" not in r
    assert m.put("/api/v1/politique/ACME", json={"tlp_plancher": "TLP:AMBER"}).status_code == 200
    p = m.put("/api/v1/politique/ACME", json={"acquittement_rapport": True}).json()
    assert p["acquittement_rapport"] is True and p["tlp_plancher"] == "TLP:AMBER"
    r = m.get("/api/v1/reports/period", params={"client": "ACME"}).json()
    assert r["acquittement_inclus"] is True and r["acquittement"][crit]["moyenne_min"] == 12.0
    aud = db.scalars(select(AuditEntry).where(AuditEntry.action == "client.politique")).all()[-1]
    assert aud.details["acquittement_rapport_avant"] is False and aud.details["acquittement_rapport"] is True


def test_horloge_du_manager_en_avance(app, db, world, alert):
    """Préproduction 27/11/2026 : manager en avance de 5 min, acquittement « avant » la détection. Délai compté 0,
    jamais négatif, et le cas est compté à part pour l'expliquer."""
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    t = _t(db, ref)
    crit = t.criticite_initiale
    t.acquitted_at, t.acquitted_by = t.detected_at - timedelta(minutes=3), "analyst_acme"
    db.commit()
    d = login(app, db, "manager").get("/api/v1/dashboard", params={"client": "ACME"}).json()["acquittement"][crit]
    assert d["moyenne_min"] == 0.0 and d["p90_min"] == 0.0 and d["horloge_en_avance"] == 1
