"""Battement de cœur de la chaîne Wazuh vers Keryx (ADR-0032, partie 3) : reconnu à son groupe avant tout seuil, jamais
de ticket ; absence au-delà du délai signalée une fois (journal d'audit, canal d'astreinte, état de l'équipe et de
l'Admin) ; retour signalé ; réglages du manager."""
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from keryx import astreinte
from keryx.models import AuditEntry, Notification, Tenant, Ticket

from .conftest import ingest, login
from .test_astreinte import FakeWebhook, _canal

BATTEMENT = {"timestamp": "2026-11-27T01:00:00.000+0000", "id": "1764205200.1",
             "rule": {"id": "119990", "level": 3, "description": "Keryx : battement de cœur de la chaîne d'alerte",
                      "groups": ["keryx_battement"]},
             "agent": {"id": "000", "name": "wazuh-manager-01"}, "manager": {"name": "wazuh-manager-01"},
             "full_log": "Nov 27 01:00:00 wazuh-manager-01 keryx-battement: battement de la chaîne vers Keryx"}


@pytest.fixture
def hook(tmp_path, settings):
    d = tmp_path / "pki"
    d.mkdir()
    h = FakeWebhook(d)
    settings.astreinte_allow_loopback, settings.astreinte_ca_file = True, h.ca
    yield h
    h.stop()


def _tenant(db, key="ACME"):
    db.rollback()
    db.expire_all()
    return db.scalars(select(Tenant).where(Tenant.key == key)).one()


def _tick(app, settings, now):
    return astreinte.tick(sessionmaker(bind=app.state.engine), settings, now=now)


def test_battement_jamais_de_ticket_meme_sous_le_seuil(app, db, world):
    r = ingest(app, world["keys"]["ACME"], BATTEMENT)
    assert r.status_code == 202 and r.json() == {"status": "battement"}
    t = _tenant(db)
    assert t.battement_at is not None and t.battement_source == "wazuh-manager-01"
    assert db.scalars(select(Ticket)).all() == []
    assert not db.scalars(select(AuditEntry).where(AuditEntry.action.like("battement%"))).all()   # pas d'audit à chaque battement


def test_reglages_du_manager(app, db, world):
    m = login(app, db, "manager")
    r = m.put("/api/v1/politique/ACME", json={"battement_periode_min": 10, "battement_delai_min": 15})
    assert r.status_code == 422 and "deux périodes" in r.json()["detail"]
    r = m.put("/api/v1/politique/ACME", json={"battement_active": True, "battement_periode_min": 5, "battement_delai_min": 20})
    assert r.status_code == 200 and r.json()["battement"]["active"] is True and r.json()["battement"]["delai_min"] == 20
    assert _tenant(db).battement_depuis is not None
    aud = db.scalars(select(AuditEntry).where(AuditEntry.action == "client.politique")).all()[-1]
    assert aud.details["battement"] == {"active": True, "periode": 5, "delai": 20}
    for qui in ("client_acme", "admin"):
        assert login(app, db, qui).get("/api/v1/battements").status_code == 403
    assert [x["key"] for x in login(app, db, "analyst_acme").get("/api/v1/battements").json()["items"]] == ["ACME"]


def test_absence_signalee_une_fois_puis_retour(app, db, world, hook, settings):
    adm = login(app, db, "admin")
    canal = _canal(adm, "astreinte-soc", f"{hook.url}/hooks/astreinte")
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"battement_active": True, "astreinte_canal_id": canal["id"]}).status_code == 200
    ingest(app, world["keys"]["ACME"], BATTEMENT)
    t = _tenant(db)
    dernier = t.battement_at
    assert _tick(app, settings, dernier + timedelta(minutes=14))["battements_manquants"] == 0
    assert _tick(app, settings, dernier + timedelta(minutes=16))["battements_manquants"] == 1
    assert _tick(app, settings, dernier + timedelta(minutes=40))["battements_manquants"] == 0       # une seule fois
    assert len(hook.requests) == 1 and hook.json()["type"] == "keryx.battement_manquant"
    assert hook.json()["client"] == "ACME" and hook.json()["minutes"] == 16 and hook.json()["source"] == "wazuh-manager-01"
    db.rollback()
    n = db.scalars(select(Notification).where(Notification.motif == "battement")).one()
    assert n.ticket_id is None and n.status == "envoye"
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "battement.manquant")).one().actor == "keryx"
    etat = login(app, db, "analyst_acme").get("/api/v1/battements").json()["items"][0]
    assert etat["manquant_depuis"] is not None
    assert adm.get("/api/v1/admin/system").json()["battements_manquants"] == ["ACME"]
    # retour : signalé, état effacé
    assert _tenant(db).battement_manquant_at is not None, "absence non enregistrée"
    assert ingest(app, world["keys"]["ACME"], BATTEMENT).status_code == 202
    assert len(hook.requests) == 2 and hook.json()["type"] == "keryx.battement_retabli"
    assert _tenant(db).battement_manquant_at is None
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "battement.retabli")).one()
    assert adm.get("/api/v1/admin/system").json()["battements_manquants"] == []


def test_client_active_mais_jamais_branche(app, db, world, settings):
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"battement_active": True}).status_code == 200
    depuis = _tenant(db).battement_depuis
    assert _tick(app, settings, depuis + timedelta(minutes=16))["battements_manquants"] == 1     # sans canal : audit seul
    db.rollback()
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "battement.manquant")).one()
    # désactiver efface l'alerte ; un client sans battement activé n'est jamais signalé
    assert m.put("/api/v1/politique/ACME", json={"battement_active": False}).status_code == 200
    assert _tenant(db).battement_manquant_at is None
    assert _tick(app, settings, depuis + timedelta(days=2))["battements_manquants"] == 0
