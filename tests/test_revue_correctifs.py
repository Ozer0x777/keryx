"""Régressions de la revue de code : courriels, notifications, rapports, rétention, crise."""
from datetime import timedelta

from sqlalchemy import select

from keryx import notify
from keryx.api import create_app
from keryx.ids import utcnow
from keryx.inbox import push
from keryx.models import InboxItem, Notification, RawAlert, Ticket, User

from .conftest import ALERT_CRITICAL, ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login
from .test_notifications import FakeSMTP, _contacts


def test_courriel_en_echec_sur_toute_exception(settings, db, request, monkeypatch):
    """Une exception inattendue (pas seulement SMTP/OS) ne laisse plus le courriel « en_attente » pour toujours."""
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host = "smtp.example.eu"
    app = create_app(settings)
    world = request.getfixturevalue("world")
    _contacts(db, world, emails=("rssi@acme.example",))

    def boom(*a, **k):
        raise ValueError("bug inattendu")
    monkeypatch.setattr(notify, "_send", boom)
    ingest(app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    n = db.scalars(select(Notification)).one()
    assert n.status == "echec" and n.attempts == 1


def test_relance_prise_atomique_pas_de_double_envoi(settings, db, request, monkeypatch):
    FakeSMTP.sent, FakeSMTP.fail = [], True
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host = "smtp.example.eu"
    app = create_app(settings)
    world = request.getfixturevalue("world")
    _contacts(db, world, emails=("rssi@acme.example",))
    ingest(app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    FakeSMTP.fail = False
    factory = app.state.SessionLocal
    later = utcnow() + timedelta(minutes=10)
    # Un autre worker a déjà pris ce courriel entre la lecture et la prise : il n'est pas renvoyé une seconde fois
    real_send = notify.send_pending
    taken = {"n": 0}

    def steal_first(sf, st, ids):
        taken["n"] += 1
        return real_send(sf, st, ids)
    monkeypatch.setattr(notify, "send_pending", steal_first)
    s = factory()
    s.execute(Notification.__table__.update().values(status="envoye"))   # l'autre worker l'a déjà traité
    s.commit(); s.close()
    assert notify.retry_failed(factory, settings, now=later) == 0
    assert FakeSMTP.sent == []


def test_notification_concurrente_ne_leve_pas_d_erreur(app, db, world, alert, monkeypatch):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    user = db.scalars(select(User).where(User.username == "analyst_acme")).one()
    assert push(db, user, "echeance", "ACME-1", dedup_key="echeance:ACME-1:x") is True
    db.commit()
    assert push(db, user, "echeance", "ACME-1", dedup_key="echeance:ACME-1:x") is False   # déjà déposée
    # Course : la vérification préalable ne voit rien (l'autre requête n'a pas encore validé), l'insertion se heurte
    # à la contrainte d'unicité. Avant le correctif : IntegrityError, donc erreur 500 sur /notifications.
    import keryx.inbox as inbox
    original = inbox.select
    monkeypatch.setattr(inbox, "select", lambda *a, **k: original(*a, **k).where(InboxItem.id == "aveugle"))
    assert push(db, user, "echeance", "ACME-1", dedup_key="echeance:ACME-1:x") is False
    monkeypatch.undo()
    assert db.query(InboxItem).filter_by(dedup_key="echeance:ACME-1:x").count() == 1


def test_rapports_plafond_sur_la_periode_et_statuts_en_sql(app, db, world, alert, monkeypatch):
    import keryx.routes_reports as rr
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    old = utcnow() - timedelta(days=200)
    row = db.scalars(select(Ticket).where(Ticket.ref == "ACME-1")).one()
    row.created_at = row.detected_at = row.updated_at = row.closed_at = old
    row.status = "faux_positif"            # clos il y a 200 jours : hors de toute période récente
    db.commit()
    m = login(app, db, "manager")
    monkeypatch.setattr(rr, "MAX_TICKETS", 1)
    # Le ticket clos il y a 200 jours est hors période : seul ACME-2 (ouvert) est chargé, le plafond de 1 tient
    assert m.get("/api/v1/dashboard", params={"client": "ACME"}).status_code == 200
    # Sur toute la période, 2 tickets dépassent le plafond de 1 : refus explicite plutôt qu'un rapport tronqué
    wide = m.get("/api/v1/dashboard", params={"client": "ACME", "from": (utcnow() - timedelta(days=250)).date().isoformat()})
    assert wide.status_code == 422
    monkeypatch.setattr(rr, "MAX_TICKETS", 20000)
    d = m.get("/api/v1/dashboard", params={"client": "ACME"}).json()
    assert d["by_status"] == {"nouveau": 1, "faux_positif": 1}  # décompte sur tous les tickets, pas seulement la période


def test_retention_exige_un_ticket_clos_depuis_plus_longtemps_que_la_duree(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    old = utcnow() - timedelta(days=30 * 13)
    for ra in db.scalars(select(RawAlert)).all():
        ra.received_at = old                       # alerte ancienne…
    db.commit()                                    # …mais ticket clos À L'INSTANT : sa clôture est récente
    adm = login(app, db, "admin")
    assert adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()["total"] == 0
    db.scalars(select(Ticket)).one().closed_at = old
    db.commit()
    assert adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()["total"] == 1


def test_crise_refusee_sur_ticket_clos_et_desactivee_par_la_fusion(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["ACME"], alert(ALERT_NO_MITRE))
    m = login(app, db, "manager")
    assert m.post("/api/v1/tickets/ACME-2/crisis", json={"active": True, "reason": "test crise"}).status_code == 200
    m.post("/api/v1/tickets/ACME-2/crisis/entries", json={"kind": "decision", "body": "isoler"})
    # La fusion clôt le ticket source : la crise s'arrête avec lui
    assert m.post("/api/v1/tickets/ACME-2/merge", json={"into": "ACME-1", "reason": "doublon"}).status_code == 200
    state = m.get("/api/v1/tickets/ACME-2/crisis").json()
    assert state["active"] is False
    # Plus d'entrée ni de coche sur un ticket clos
    assert m.post("/api/v1/tickets/ACME-2/crisis/entries", json={"kind": "decision", "body": "tard"}).status_code in (409,)
    row = db.scalars(select(Ticket).where(Ticket.ref == "ACME-2")).one()
    row.crisis = True            # état incohérent forcé : même alors, le ticket clos refuse toute modification
    db.commit()
    assert m.post("/api/v1/tickets/ACME-2/crisis/entries", json={"kind": "decision", "body": "tard"}).status_code == 409
    m.post("/api/v1/tickets/ACME-1/crisis", json={"active": True, "reason": "autre"})
    m.post("/api/v1/tickets/ACME-1/crisis/entries", json={"kind": "action", "body": "agir"})
    entry = m.get("/api/v1/tickets/ACME-1/crisis").json()["items"][0]
    m.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    m.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    m.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    assert m.patch(f"/api/v1/tickets/ACME-1/crisis/entries/{entry['id']}", json={"done": True}).status_code == 409
