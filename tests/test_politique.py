"""Politique du client (ADR-0033) : TLP plancher réglé par le manager. Les tickets et les pièces naissent au plancher,
un analyste ne descend pas en dessous, un manager le peut avec un motif ; relever le plancher relève les tickets
ouverts, le baisser ne baisse rien. Cloisonnement : un manager ne règle que ses clients, ni l'analyste, ni le client,
ni l'Admin ne règlent rien."""
import io
import zipfile

from sqlalchemy import select

from keryx.models import Attachment, AuditEntry, Ticket, TicketEvent

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login

REGISTRE = {"description": "Journaux d'authentification", "collected_at": "2026-11-20T14:50:00Z",
            "method": "Export via l'agent"}


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("auth.log", "x")
    return buf.getvalue()


def _ticket(db, ref):
    db.rollback()
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.ref == ref)).one()


def test_sans_plancher_comportement_inchange(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    assert _ticket(db, ref).tlp == "TLP:AMBER"
    a = login(app, db, "analyst_acme")
    assert a.post(f"/api/v1/tickets/{ref}/qualification", json={"tlp": "TLP:CLEAR"}).status_code == 200
    assert a.get(f"/api/v1/tickets/{ref}").json()["tlp_plancher"] is None


def test_plancher_releve_les_ouverts_et_s_applique(app, db, world, alert):
    ouvert = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    clos = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    t = _ticket(db, clos)
    t.status = "cloture"
    db.commit()
    m = login(app, db, "manager")
    r = m.put("/api/v1/politique/acme", json={"tlp_plancher": "TLP:AMBER+STRICT"})
    assert r.status_code == 200 and r.json()["tickets_releves"] == [ouvert]
    assert _ticket(db, ouvert).tlp == "TLP:AMBER+STRICT" and _ticket(db, clos).tlp == "TLP:AMBER"   # clos : inchangé
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "tlp_releve")).one()
    assert ev.details == {"de": "TLP:AMBER", "vers": "TLP:AMBER+STRICT", "plancher": "TLP:AMBER+STRICT"} and ev.actor == "manager"
    aud = db.scalars(select(AuditEntry).where(AuditEntry.action == "client.politique")).one()
    assert aud.details["tlp_plancher"] == "TLP:AMBER+STRICT" and aud.details["tickets_releves"] == 1
    # un nouveau ticket naît au plancher ; une pièce sans sensibilité aussi ; en dessous : refusée
    alerte = alert(ALERT_SSH_BRUTEFORCE)
    alerte["agent"]["id"], alerte["agent"]["name"] = "077", "autre-poste"
    nouveau = ingest(app, world["keys"]["ACME"], alerte).json()["ticket"]
    assert _ticket(db, nouveau).tlp == "TLP:AMBER+STRICT"
    a = login(app, db, "analyst_acme")
    up = a.post(f"/api/v1/tickets/{ouvert}/attachments", data=REGISTRE, files={"file": ("p.zip", _zip(), "application/zip")})
    assert up.status_code == 201, up.text
    db.expire_all()
    assert db.scalars(select(Attachment)).all()[-1].sensitivity == "TLP:AMBER+STRICT"
    bas = a.post(f"/api/v1/tickets/{ouvert}/attachments", data={**REGISTRE, "sensitivity": "TLP:GREEN"},
                 files={"file": ("q.zip", _zip(), "application/zip")})
    assert bas.status_code == 422 and "AMBER+STRICT" in bas.text
    # la fiche donne le plancher à l'équipe, pas au client
    assert a.get(f"/api/v1/tickets/{ouvert}").json()["tlp_plancher"] == "TLP:AMBER+STRICT"
    assert "tlp_plancher" not in login(app, db, "client_acme").get(f"/api/v1/tickets/{ouvert}").json()


def test_analyste_monte_manager_descend_avec_motif(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    m, a = login(app, db, "manager"), login(app, db, "analyst_acme")
    assert m.put("/api/v1/politique/ACME", json={"tlp_plancher": "TLP:AMBER"}).status_code == 200
    r = a.post(f"/api/v1/tickets/{ref}/qualification", json={"tlp": "TLP:GREEN"})
    assert r.status_code == 422 and "TLP:AMBER" in r.json()["detail"]
    assert a.post(f"/api/v1/tickets/{ref}/qualification", json={"tlp": "TLP:RED"}).status_code == 200    # monter : oui
    assert m.post(f"/api/v1/tickets/{ref}/qualification", json={"tlp": "TLP:GREEN"}).status_code == 422  # sans motif
    assert m.post(f"/api/v1/tickets/{ref}/qualification", json={"tlp": "TLP:GREEN", "motif_tlp": "court"}).status_code == 422
    r = m.post(f"/api/v1/tickets/{ref}/qualification",
               json={"tlp": "TLP:GREEN", "motif_tlp": "Partage convenu avec le client pour ce ticket"})
    assert r.status_code == 200 and _ticket(db, ref).tlp == "TLP:GREEN"
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "tlp_sous_plancher")).one()
    assert ev.details["motif"].startswith("Partage convenu") and ev.details["plancher"] == "TLP:AMBER"
    assert not ev.visible_client
    # baisser le plancher ne baisse aucun ticket
    assert m.put("/api/v1/politique/ACME", json={"tlp_plancher": "TLP:CLEAR"}).json()["tickets_releves"] == []
    assert _ticket(db, ref).tlp == "TLP:GREEN"


def test_qui_regle_la_politique(app, db, world):
    m = login(app, db, "manager")
    assert [x["key"] for x in m.get("/api/v1/politique").json()["items"]] == ["ACME", "DELTA"]
    assert m.put("/api/v1/politique/ZZZ", json={"tlp_plancher": "TLP:RED"}).status_code == 404
    assert m.put("/api/v1/politique/ACME", json={"tlp_plancher": "TLP:ROUGE"}).status_code == 422
    for qui in ("analyst_acme", "client_acme", "admin"):
        c = login(app, db, qui)
        assert c.get("/api/v1/politique").status_code == 403
        assert c.put("/api/v1/politique/ACME", json={"tlp_plancher": "TLP:CLEAR"}).status_code == 403
