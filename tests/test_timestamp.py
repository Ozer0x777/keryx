"""Horodatage de confiance RFC 3161, contre une autorité locale (openssl ts). [RFC 3161 ; ISO/IEC 27037]"""
import subprocess

import pytest
from sqlalchemy import select

from keryx import timestamping as ts
from keryx.api import create_app
from keryx.models import CustodyEvent, Timestamp

from . import tsa
from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login
from .test_attachments import REGISTRY, zip_bytes

pytestmark = pytest.mark.skipif(not tsa.have_openssl(), reason="openssl requis pour l'autorité d'horodatage de test")


@pytest.fixture
def authority(tmp_path):
    d = tmp_path / "tsa"
    d.mkdir()
    ca = tsa.make_pki(d)
    srv = tsa.Tsa(d)
    yield srv, ca
    srv.stop()


@pytest.fixture
def stamped_app(settings, authority):
    srv, ca = authority
    settings.tsa_url, settings.tsa_ca_file = srv.url, ca
    return create_app(settings)


def attachment(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", zip_bytes(), "application/zip")})
    return a, r.json()


def test_horodatage_piece_verification_et_telechargement(stamped_app, db, world, alert):
    a, att = attachment(stamped_app, db, world, alert)
    r = a.post(f"/api/v1/attachments/{att['id']}/timestamp")
    assert r.status_code == 201 and r.json()["serial"] and r.json()["gen_time"].endswith("Z")
    tid = r.json()["id"]
    assert a.get(f"/api/v1/attachments/{att['id']}/timestamps").json()["items"][0]["id"] == tid
    assert a.post(f"/api/v1/timestamps/{tid}/verify").json()["valid"] is True
    tok = a.get(f"/api/v1/timestamps/{tid}/token")
    assert tok.headers["content-type"] == "application/timestamp-reply" and len(tok.content) > 500
    # chaîne de possession et registre des actions
    db.expire_all()
    assert "horodatage" in [c.action for c in db.scalars(select(CustodyEvent))]
    assert any(e["action"] == "horodatage" for e in a.get("/api/v1/tickets/ACME-1").json()["events"])
    # Le jeton conservé est lié à la pièce : modifié en base, la vérification échoue
    db.rollback()                                      # fin du snapshot de lecture avant d'écrire
    row = db.scalars(select(Timestamp)).one()
    row.message = row.message[:-1] + ("0" if row.message[-1] != "0" else "1")
    db.commit()
    bad = a.post(f"/api/v1/timestamps/{tid}/verify").json()
    assert bad["valid"] is False and "non valide" in bad["error"]


def test_cloisonnement_et_droits(stamped_app, db, world, alert):
    a, att = attachment(stamped_app, db, world, alert)
    tid = a.post(f"/api/v1/attachments/{att['id']}/timestamp").json()["id"]
    assert login(stamped_app, db, "analyst_delta").post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 404
    other = login(stamped_app, db, "analyst_delta")
    assert other.get(f"/api/v1/timestamps/{tid}/token").status_code == 404
    assert other.post(f"/api/v1/timestamps/{tid}/verify").status_code == 404
    assert login(stamped_app, db, "client_acme").post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 403
    assert login(stamped_app, db, "admin").get(f"/api/v1/timestamps/{tid}/token").status_code == 404   # pas d'accès au contenu


def test_non_configure_ou_autorite_defaillante(app, settings, db, world, alert, authority):
    a, att = attachment(app, db, world, alert)
    assert a.post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 409            # désactivé par défaut
    srv, ca = authority
    settings.tsa_url, settings.tsa_ca_file = srv.url, ca
    app2 = create_app(settings)
    a2 = login(app2, db, "analyst_acme")
    srv.mode = "500"
    assert a2.post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 502
    srv.mode = "junk"
    assert a2.post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 502
    srv.mode = "ok"
    assert a2.post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 201
    db.expire_all()
    assert db.query(Timestamp).count() == 1                       # aucun jeton conservé pour les échecs


def test_reponse_d_une_autre_autorite_refusee(settings, authority, tmp_path):
    """Une réponse signée par une autorité dont la racine n'est pas configurée est rejetée."""
    srv, _ca = authority
    other = tmp_path / "autre"
    other.mkdir()
    other_ca = tsa.make_pki(other)
    with pytest.raises(ts.TimestampError, match="non valide"):
        ts.stamp(srv.url, ts.message_for("attachment", "x", "ab" * 32), other_ca)
    with pytest.raises(ts.TimestampError, match="non configuré"):
        ts.stamp(srv.url, b"x", None)


def test_point_de_controle_de_l_audit(stamped_app, db, world, alert):
    ingest(stamped_app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    adm = login(stamped_app, db, "admin")
    r = adm.post("/api/v1/audit/checkpoint/timestamp")
    assert r.status_code == 201 and r.json()["seq"] >= 1 and len(r.json()["seal"]) == 64
    items = adm.get("/api/v1/audit/timestamps").json()["items"]
    assert items[0]["seal"] == r.json()["seal"]
    assert adm.post(f"/api/v1/timestamps/{r.json()['id']}/verify").json()["valid"] is True
    m = login(stamped_app, db, "manager")
    assert m.post("/api/v1/audit/checkpoint/timestamp").status_code == 403
    assert m.get(f"/api/v1/timestamps/{r.json()['id']}/token").status_code == 403
    assert m.get("/api/v1/me").json()["features"]["timestamping"] is True


def test_autorite_reelle(tmp_path):
    """Essai contre une VRAIE autorité d'horodatage publique (ex. FreeTSA), si KERYX_TEST_TSA_REAL=« url|fichier_ca.pem »."""
    import os
    conf = os.environ.get("KERYX_TEST_TSA_REAL")
    if not conf:
        pytest.skip("KERYX_TEST_TSA_REAL non défini")
    url, ca = conf.split("|")
    msg = ts.message_for("attachment", "essai-test", "cd" * 32)
    r = ts.stamp(url, msg, ca)
    assert ts.verify(r["token"], msg, ca) == r["gen_time"]
    with pytest.raises(ts.TimestampError):
        ts.verify(r["token"], msg + b"x", ca)
    # Le jeton est vérifiable par un tiers avec openssl (message et jeton écrits tels quels)
    if tsa.have_openssl():
        (tmp_path / "t.tsr").write_bytes(r["token"])
        (tmp_path / "m.txt").write_bytes(msg)
        out = subprocess.run(["openssl", "ts", "-verify", "-in", str(tmp_path / "t.tsr"), "-data", str(tmp_path / "m.txt"), "-CAfile", ca],
                             capture_output=True, text=True)
        assert "Verification: OK" in out.stdout + out.stderr
