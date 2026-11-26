"""Contenu du ticket (PDIS IV.2.1.w) : niveau de classification (IGI 1300 / II 901), version de la règle déclenchée,
collecteur (manager Wazuh) ; réglages du manager ; registre ; seul un manager abaisse la classification."""
from sqlalchemy import select

from keryx.models import Ticket

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login


def _t(db, ref):
    db.rollback()
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.ref == ref)).one()


def test_ticket_porte_classification_version_et_collecteur(app, db, world, alert):
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"niveau_classification_defaut": "Diffusion Restreinte",
                                                "version_regles": "wazuh-4.9.1 + local 2026-11-20"}).status_code == 200
    a1 = alert(ALERT_CRITICAL)
    a1["manager"] = {"name": "wazuh-manager-01"}
    ref = ingest(app, world["keys"]["ACME"], a1).json()["ticket"]
    a2 = alert(ALERT_SSH_BRUTEFORCE)
    a2["rule"]["version"] = "3"
    ref2 = ingest(app, world["keys"]["ACME"], a2).json()["ticket"]
    t = _t(db, ref)
    assert (t.niveau_classification, t.rule_version, t.collecteur) == ("Diffusion Restreinte", "wazuh-4.9.1 + local 2026-11-20", "wazuh-manager-01")
    assert _t(db, ref2).rule_version == "3"          # la version portée par l'alerte prime
    for qui in ("analyst_acme", "client_acme"):
        fiche = login(app, db, qui).get(f"/api/v1/tickets/{ref}").json()
        assert fiche["niveau_classification"] == "Diffusion Restreinte" and fiche["collecteur"] == "wazuh-manager-01"
        assert fiche["rule"]["version"] == "wazuh-4.9.1 + local 2026-11-20"
    reg = login(app, db, "analyst_acme").get("/api/v1/registre", params={"client": "ACME"}).json()["items"]
    ligne = next(x for x in reg if x["reference"] == ref)
    assert ligne["niveau_classification"] == "Diffusion Restreinte" and ligne["collecteur"] == "wazuh-manager-01"


def test_seul_un_manager_abaisse_la_classification(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    assert _t(db, ref).niveau_classification == "Non protégé"
    a = login(app, db, "analyst_acme")
    assert a.post(f"/api/v1/tickets/{ref}/qualification", json={"niveau_classification": "Secret"}).status_code == 422
    assert a.post(f"/api/v1/tickets/{ref}/qualification", json={"niveau_classification": "Diffusion Restreinte"}).status_code == 200
    assert a.post(f"/api/v1/tickets/{ref}/qualification", json={"niveau_classification": "Non protégé"}).status_code == 422
    m = login(app, db, "manager")
    assert m.post(f"/api/v1/tickets/{ref}/qualification", json={"niveau_classification": "Non protégé"}).status_code == 200
    assert m.put("/api/v1/politique/ACME", json={"niveau_classification_defaut": "Confidentiel"}).status_code == 422


def test_collecteur_lu_dans_l_alerte_brute_d_un_ancien_ticket(app, db, world, alert):
    a1 = alert(ALERT_CRITICAL)
    a1["manager"] = {"name": "wazuh-ancien"}
    ref = ingest(app, world["keys"]["ACME"], a1).json()["ticket"]
    t = _t(db, ref)
    t.collecteur = None
    db.commit()
    assert login(app, db, "analyst_acme").get(f"/api/v1/tickets/{ref}").json()["collecteur"] == "wazuh-ancien"
