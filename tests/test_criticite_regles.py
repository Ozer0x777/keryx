"""Criticité initiale imposée par règle Wazuh, réglée par le manager pour chaque client : aucune règle en dur, le
niveau Wazuh reste le seuil d'entrée, l'origine de la criticité est tracée, les autres clients ne sont pas touchés."""
from sqlalchemy import select

from keryx.models import Ticket, TicketEvent

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login


def _t(db, ref):
    db.rollback()
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.ref == ref)).one()


def test_criticite_imposee_par_regle(app, db, world, alert):
    regle = ALERT_SSH_BRUTEFORCE["rule"]["id"]
    sans = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    calculee = _t(db, sans).criticite_initiale
    m = login(app, db, "manager")
    r = m.put("/api/v1/politique/ACME", json={"criticite_regles": {regle: "Critique"}})
    assert r.status_code == 200 and r.json()["criticite_regles"] == {regle: "Critique"}
    a2 = alert(ALERT_SSH_BRUTEFORCE)
    a2["id"], a2["agent"]["id"] = "1732113662.9", "099"
    avec = ingest(app, world["keys"]["ACME"], a2).json()["ticket"]
    assert calculee != "Critique" and _t(db, avec).criticite_initiale == "Critique"
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "creation")).all()[-1]
    assert ev.details["criticite_source"] == "regle_client"
    delta = ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    assert _t(db, delta).criticite_initiale == calculee                       # autre client : inchangé
    assert m.put("/api/v1/politique/ACME", json={"criticite_regles": {regle: "Énorme"}}).status_code == 422
    assert m.put("/api/v1/politique/ACME", json={"criticite_regles": {"règle avec espace": "Faible"}}).status_code == 422
    assert m.put("/api/v1/politique/ACME", json={"criticite_regles": {}}).json()["criticite_regles"] == {}
    assert login(app, db, "analyst_acme").put("/api/v1/politique/ACME", json={"criticite_regles": {regle: "Faible"}}).status_code == 403


def test_une_regle_pour_plusieurs_ou_tous_les_clients(app, db, world):
    m = login(app, db, "manager")
    r = m.put("/api/v1/politique/criticite-regles", json={"regle": "60148", "criticite": "Élevée"})     # tous
    assert r.status_code == 200 and r.json()["clients"] == ["ACME", "DELTA"]
    items = {x["key"]: x["criticite_regles"] for x in m.get("/api/v1/politique").json()["items"]}
    assert items == {"ACME": {"60148": "Élevée"}, "DELTA": {"60148": "Élevée"}}
    assert m.put("/api/v1/politique/criticite-regles", json={"regle": "92201", "criticite": "Critique", "clients": ["acme"]}).json()["clients"] == ["ACME"]
    assert m.put("/api/v1/politique/criticite-regles", json={"regle": "60148", "criticite": None, "clients": ["DELTA"]}).status_code == 200
    items = {x["key"]: x["criticite_regles"] for x in m.get("/api/v1/politique").json()["items"]}
    assert items == {"ACME": {"60148": "Élevée", "92201": "Critique"}, "DELTA": {}}
    assert m.put("/api/v1/politique/criticite-regles", json={"regle": "1", "criticite": "Faible", "clients": ["ACME", "ZZZ"]}).status_code == 404
    assert "1" not in {x["key"]: x["criticite_regles"] for x in m.get("/api/v1/politique").json()["items"]}["ACME"]
    assert m.put("/api/v1/politique/criticite-regles", json={"regle": "a b", "criticite": "Faible"}).status_code == 422
    assert login(app, db, "analyst_acme").put("/api/v1/politique/criticite-regles", json={"regle": "1", "criticite": "Faible"}).status_code == 403
