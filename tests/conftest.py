import copy
import os
import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from keryx import security
from keryx.api import create_app
from keryx.config import Settings
from keryx.db import make_engine, make_session_factory
from keryx.models import ApiKey, MitreMapping, Tenant, User

PASSWORD = "correct-horse-battery-staple"

# Alertes Wazuh simulées (structure des alertes JSON Wazuh 4.x).
ALERT_SSH_BRUTEFORCE = {
    "timestamp": "2026-11-20T14:41:02.118+0000",
    "id": "1732113662.4417203",
    "rule": {
        "id": "5712", "level": 10,
        "description": "sshd: brute force trying to get access to the system. Authentication failed.",
        "groups": ["syslog", "sshd", "authentication_failures"],
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        "pci_dss": ["11.4", "10.2.4"], "gdpr": ["IV_35.7.d", "IV_32.2"],
    },
    "agent": {"id": "003", "name": "srv-web-01", "ip": "10.20.1.15", "labels": {"importance": "sensible"}},
    "manager": {"name": "wazuh-manager-01"},
    "decoder": {"name": "sshd"},
    "data": {"srcip": "185.220.101.4", "srcuser": "root"},
    "location": "/var/log/auth.log",
    "full_log": "Nov 20 14:41:02 srv-web-01 sshd[2211]: Failed password for root from 185.220.101.4 port 51344 ssh2",
}

ALERT_NO_MITRE = {
    "timestamp": "2026-11-20T15:00:00.000+0000",
    "id": "1732114800.1",
    "rule": {"id": "100200", "level": 8, "description": "Custom: repeated authentication failures",
             "groups": ["custom", "authentication_failures"]},
    "agent": {"id": "004", "name": "pc-rh-03"},
}

ALERT_LOW = {
    "timestamp": "2026-11-20T15:01:00.000+0000",
    "id": "1732114860.2",
    "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user"},
    "agent": {"id": "003", "name": "srv-web-01"},
}

ALERT_XSS = {
    "timestamp": "2026-11-20T15:02:00.000+0000",
    "id": "1732114920.3",
    "rule": {"id": "31151", "level": 10, "description": "<script>alert(1)</script> web attack",
             "groups": ["web"]},
    "agent": {"id": "009", "name": "<img src=x onerror=alert(1)>"},
    "full_log": "GET /?q=<script>alert(document.cookie)</script> HTTP/1.1",
}

ALERT_CRITICAL = {
    "timestamp": "2026-11-20T13:58:00.000+0000",
    "id": "1732111080.9",
    "rule": {"id": "100900", "level": 15, "description": "Correlated exfiltration to external IP",
             "groups": ["exfiltration"],
             "mitre": {"id": ["T1048"], "tactic": ["Exfiltration"],
                       "technique": ["Exfiltration Over Alternative Protocol"]}},
    "agent": {"id": "021", "name": "srv-files-02", "labels": {"importance": "vital"}},
}


@pytest.fixture
def alert():
    return lambda a: copy.deepcopy(a)


SECRET_KEY = security.new_secret_key()


def _pg_database():
    """Base PostgreSQL jetable pour un test (si KERYX_TEST_PG_URL est défini, ex. postgresql+psycopg://u:p@h/postgres)."""
    import uuid

    import psycopg
    from sqlalchemy.engine import make_url
    admin = make_url(os.environ["KERYX_TEST_PG_URL"])
    name = "keryx_t_" + uuid.uuid4().hex[:12]
    dsn = admin.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')

    def drop():
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    return admin.set(database=name).render_as_string(hide_password=False), drop


@pytest.fixture
def settings(tmp_path):
    drop = None
    url = f"sqlite:///{tmp_path}/test.db"
    if os.environ.get("KERYX_TEST_PG_URL"):
        url, drop = _pg_database()
    yield Settings(database_url=url, cookie_secure=False, auto_create_schema=True,
                   secret_key=SECRET_KEY, attachments_dir=str(tmp_path / "pj"), smtp_host=None,
                   clamav_host=None, web_dist=str(tmp_path / "no_web"))
    if drop:
        import gc
        gc.collect()  # libère les moteurs avant de supprimer la base
        drop()


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def db(app, settings):
    # Session de test en BEGIN différé : ses lectures ne bloquent pas l'application.
    s = make_session_factory(make_engine(settings.database_url, immediate=False))()
    yield s
    s.close()


@pytest.fixture
def world(app, db):
    """Deux clients, des utilisateurs de chaque rôle, une clé d'ingestion par client."""
    acme = Tenant(key="ACME", name="ACME Industrie")
    delta = Tenant(key="DELTA", name="Transports Delta")
    db.add_all([acme, delta]); db.flush()
    pw = security.hash_password(PASSWORD)
    users = {}
    for username, role, tenants in [
        ("admin", "admin", []),
        ("manager", "manager", [acme, delta]),
        ("analyst_acme", "analyst", [acme]),
        ("analyst_delta", "analyst", [delta]),
        ("client_acme", "client", [acme]),
        ("client_delta", "client", [delta]),
    ]:
        u = User(username=username, display_name=username, role=role, password_hash=pw,
                 totp_secret="", recovery_codes=[], tenants=tenants)
        db.add(u); db.flush()
        u.totp_secret = app.state.box.encrypt(security.new_totp_secret(), f"totp:{u.id}")
        users[username] = u
    keys = {}
    for t in (acme, delta):
        plain, prefix, digest = security.new_api_key()
        db.add(ApiKey(tenant_id=t.id, name=f"wazuh-{t.key.lower()}", prefix=prefix, key_hash=digest))
        keys[t.key] = plain
    db.add(MitreMapping(rule_group="authentication_failures", technique_id="T1110",
                        technique_name="Brute Force", tactic="Credential Access", created_by="test"))
    db.commit()
    return {"tenants": {"ACME": acme, "DELTA": delta}, "users": users, "keys": keys}


def totp_secret(app, user) -> str:
    return app.state.box.decrypt(user.totp_secret, f"totp:{user.id}")


def next_code(app, db, username: str) -> str:
    """Code TOTP valide et jamais utilisé : pas courant, ou suivant s'il a déjà servi (fenêtre ±1)."""
    user = db.query(User).filter_by(username=username).one()
    db.refresh(user)
    step = int(time.time()) // 30
    if user.last_totp_step is not None and user.last_totp_step >= step:
        step = user.last_totp_step + 1
    code = pyotp.TOTP(totp_secret(app, user)).at(step * 30)
    db.rollback()  # libère la transaction de lecture (SQLite : BEGIN IMMEDIATE)
    return code


def login(app, db, username: str) -> TestClient:
    """Connexion complète (mot de passe + TOTP). Renvoie un client avec l'en-tête CSRF prêt."""
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    r = c.post("/api/v1/auth/totp", json={"code": next_code(app, db, username)})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def ingest(app, key: str, payload: dict):
    return TestClient(app).post("/api/v1/ingest/wazuh", json=payload, headers={"Authorization": f"Bearer {key}"})
