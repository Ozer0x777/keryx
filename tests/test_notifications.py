"""Notifications e-mail. [PDIS IV.2.3.g, h, j ; RFC 3207 STARTTLS]"""
import smtplib

import pytest
from sqlalchemy import select

from keryx import notify
from keryx.api import create_app
from keryx.models import Notification, Tenant

from .conftest import ALERT_SSH_BRUTEFORCE, ingest


class FakeSMTP:
    sent: list = []
    fail = False

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.tls = host, port, False

    def starttls(self, context=None):
        assert context is not None and context.verify_mode.name == "CERT_REQUIRED"
        self.tls = True

    def login(self, user, password):
        self.user = user

    def send_message(self, msg):
        if FakeSMTP.fail:
            raise smtplib.SMTPServerDisconnected("panne")
        assert self.tls, "jamais d'envoi en clair"
        FakeSMTP.sent.append(msg)

    def quit(self):
        pass


@pytest.fixture
def smtp_app(settings, monkeypatch):
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host = "smtp.example.eu"
    return create_app(settings)


def _contacts(db, world, key="ACME", emails=("rssi@acme.example", "soc@acme.example")):
    t = db.scalars(select(Tenant).where(Tenant.key == key)).one()
    t.contact_emails = list(emails)
    db.commit()


def test_envoi_reference_seulement(smtp_app, db, request):
    world = request.getfixturevalue("world")
    _contacts(db, world)
    r = ingest(smtp_app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    assert r.status_code == 201
    assert len(FakeSMTP.sent) == 2
    msg = FakeSMTP.sent[0]
    text = msg["Subject"] + msg.get_content()
    assert "ACME-1" in text
    # Aucune information sur l'incident [PDIS IV.2.3.g]
    for secret in ("brute", "sshd", "185.220", "srv-web", "root", "5712"):
        assert secret not in text.lower()
    rows = db.scalars(select(Notification)).all()
    assert {n.status for n in rows} == {"envoye"} and {n.recipient for n in rows} == {"rssi@acme.example", "soc@acme.example"}


def test_echec_enregistre(smtp_app, db, request):
    world = request.getfixturevalue("world")
    _contacts(db, world, emails=("rssi@acme.example",))
    FakeSMTP.fail = True
    ingest(smtp_app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    assert db.scalars(select(Notification)).one().status == "echec"


def test_sans_smtp_configure(app, db, world):
    _contacts(db, world, emails=("rssi@acme.example",))
    ingest(app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    assert db.scalars(select(Notification)).one().status == "non_envoye_smtp_absent"


def test_sans_contact(app, db, world):
    ingest(app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    assert db.scalars(select(Notification)).one().status == "sans_destinataire"


def test_relance_des_echecs_avec_delai_croissant_et_plafond(smtp_app, db, request, settings):
    from datetime import timedelta

    from keryx.ids import utcnow
    world = request.getfixturevalue("world")
    _contacts(db, world, emails=("rssi@acme.example",))
    FakeSMTP.fail = True
    ingest(smtp_app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    factory = smtp_app.state.SessionLocal
    n = db.scalars(select(Notification)).one()
    assert n.status == "echec" and n.attempts == 1
    # Trop tôt : le délai de 2 minutes n'est pas écoulé
    assert notify.retry_failed(factory, settings, now=utcnow()) == 0
    # Après le délai, SMTP toujours en panne : nouvel échec, 2e essai enregistré
    later = utcnow() + timedelta(minutes=3)
    assert notify.retry_failed(factory, settings, now=later) == 1
    db.rollback(); db.refresh(n)
    assert n.status == "echec" and n.attempts == 2
    # SMTP rétabli : le courriel part, le registre le reflète
    FakeSMTP.fail = False
    assert notify.retry_failed(factory, settings, now=utcnow() + timedelta(minutes=30)) == 1
    db.rollback(); db.refresh(n)
    assert n.status == "envoye" and n.attempts == 3 and len(FakeSMTP.sent) == 1
    # Plafond d'essais : plus de relance au-delà
    n.status, n.attempts = "echec", settings.notify_max_attempts
    db.commit()
    assert notify.retry_failed(factory, settings, now=utcnow() + timedelta(days=2)) == 0
