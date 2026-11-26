"""Stratégie de notification (PDIS IV.2.3) : destinataires selon la criticité, moyen secondaire quand le courriel
échoue (une fois par ticket, numéro du ticket seulement), essai du moyen secondaire tracé, registre des
notifications par client (écran et CSV), état du système."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from keryx import notify
from keryx.models import AuditEntry, Notification, Tenant

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login
from .test_astreinte import FakeWebhook, _canal
from .test_notifications import FakeSMTP


@pytest.fixture
def hook(tmp_path, settings):
    d = tmp_path / "pki"
    d.mkdir()
    h = FakeWebhook(d)
    settings.astreinte_allow_loopback, settings.astreinte_ca_file = True, h.ca
    yield h
    h.stop()


@pytest.fixture
def smtp(settings, monkeypatch):
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host = "smtp.example.eu"
    yield FakeSMTP
    FakeSMTP.fail = False


def _contacts(app, db, emails, seuils=None):
    adm = login(app, db, "admin")
    r = adm.patch("/api/v1/admin/clients/ACME", json={"contact_emails": emails, "contacts_criticite": seuils or {}})
    assert r.status_code == 200, r.text
    return adm


def test_destinataires_selon_la_criticite(app, db, world, alert, smtp):
    adm = _contacts(app, db, ["rssi@acme.example", "soc@acme.example"], {"rssi@acme.example": "Critique"})
    assert adm.get("/api/v1/admin/clients").json()["items"][0]["contacts_criticite"] == {"rssi@acme.example": "Critique"}
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))           # non critique
    assert [m["To"] for m in smtp.sent] == ["soc@acme.example"]
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    assert sorted(m["To"] for m in smtp.sent[1:]) == ["rssi@acme.example", "soc@acme.example"]
    assert adm.patch("/api/v1/admin/clients/ACME", json={"contacts_criticite": {"soc@acme.example": "Énorme"}}).status_code == 422


def test_moyen_secondaire_quand_le_courriel_echoue(app, db, world, alert, smtp, hook):
    _contacts(app, db, ["soc@acme.example"])
    canal = _canal(login(app, db, "admin"), "sms-acme", f"{hook.url}/sms")
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"notif_secours_canal_id": canal["id"]}).status_code == 200
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    assert hook.requests == []                                                # le courriel est parti : rien d'autre
    smtp.fail = True
    ref2 = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    assert len(hook.requests) == 1
    data = hook.json()
    assert data["type"] == "keryx.notification" and data["ticket"] == ref2 and set(data) <= {"type", "ticket", "url", "envoye_le"}
    db.rollback()
    s = db.scalars(select(Notification).where(Notification.motif == "secours")).one()
    assert s.status == "envoye" and s.recipient == "sms-acme"
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "notification.secours")).one()
    # une seule fois par ticket, même si le courriel est relancé et échoue encore
    from sqlalchemy.orm import sessionmaker
    n = db.scalars(select(Notification).where(Notification.motif.is_(None), Notification.status == "echec")).one()
    notify.send_pending(sessionmaker(bind=app.state.engine), app.state.settings, [n.id])
    assert len(hook.requests) == 1 and ref != ref2


def test_sans_contact_ni_serveur_le_moyen_secondaire_prend_le_relais(app, db, world, alert, hook):
    canal = _canal(login(app, db, "admin"), "sms-acme", f"{hook.url}/sms")
    assert login(app, db, "manager").put("/api/v1/politique/ACME", json={"notif_secours_canal_id": canal["id"]}).status_code == 200
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    assert len(hook.requests) == 1


def test_essai_du_moyen_secondaire_et_etat(app, db, world, hook):
    adm = login(app, db, "admin")
    assert "ACME" in adm.get("/api/v1/admin/system").json()["sans_moyen_secondaire"]
    canal = _canal(adm, "sms-acme", f"{hook.url}/sms")
    m = login(app, db, "manager")
    assert m.post("/api/v1/politique/ACME/essai-secours").status_code == 422          # pas encore de moyen
    p = m.put("/api/v1/politique/ACME", json={"notif_secours_canal_id": canal["id"]}).json()
    assert p["notif_secours"]["essai_en_retard"] is True
    assert "ACME" in adm.get("/api/v1/admin/system").json()["secours_a_essayer"]
    r = m.post("/api/v1/politique/ACME/essai-secours").json()
    assert r["statut"] == "envoye" and r["notif_secours"]["essai_en_retard"] is False and hook.json()["type"] == "keryx.essai_notification"
    assert "ACME" not in adm.get("/api/v1/admin/system").json()["secours_a_essayer"]
    t = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    db.refresh(t)
    t.notif_secours_teste_at = t.notif_secours_teste_at - timedelta(days=200)
    db.commit()
    assert "ACME" in adm.get("/api/v1/admin/system").json()["secours_a_essayer"]
    assert login(app, db, "analyst_acme").post("/api/v1/politique/ACME/essai-secours").status_code == 403


def test_registre_des_notifications(app, db, world, alert, smtp):
    _contacts(app, db, ["soc@acme.example"])
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    a = login(app, db, "analyst_acme")
    items = a.get("/api/v1/registre-notifications", params={"client": "ACME"}).json()["items"]
    assert items[0]["ticket"] == ref and items[0]["destinataire"] == "soc@acme.example" and items[0]["statut"] == "envoye"
    assert ref in items[0]["objet"] and items[0]["mode"] == "email"
    csv = a.get("/api/v1/registre-notifications", params={"client": "ACME", "format": "csv"})
    assert csv.status_code == 200 and ref in csv.text and csv.text.startswith("date,ticket,mode")
    assert a.get("/api/v1/registre-notifications", params={"client": "DELTA"}).status_code == 404
    assert login(app, db, "client_acme").get("/api/v1/registre-notifications", params={"client": "ACME"}).status_code == 403
