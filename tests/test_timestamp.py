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


def test_autorite_exigeant_une_authentification(settings, authority):
    srv, ca = authority
    srv.auth = "keryx:mot-de-passe-tsa"
    msg = ts.message_for("attachment", "x", "ab" * 32)
    with pytest.raises(ts.TimestampError, match="refuse l'authentification"):
        ts.stamp(srv.url, msg, ca)                                      # sans identifiants
    settings.tsa_user, settings.tsa_password = "keryx", "faux"
    with pytest.raises(ts.TimestampError, match="authentification"):
        ts.stamp(srv.url, msg, ca, http=ts.make_client(settings))
    settings.tsa_password = "mot-de-passe-tsa"
    assert ts.stamp(srv.url, msg, ca, http=ts.make_client(settings))["serial"]
    # Jeton « Bearer » : en-tête envoyé tel quel (l'autorité de test n'accepte que Basic : refus attendu)
    settings.tsa_user = settings.tsa_password = None
    settings.tsa_bearer = "jeton"
    with pytest.raises(ts.TimestampError, match="authentification"):
        ts.stamp(srv.url, msg, ca, http=ts.make_client(settings))


def test_politique_d_horodatage_attendue(authority):
    srv, ca = authority
    msg = ts.message_for("attachment", "x", "ab" * 32)
    r = ts.stamp(srv.url, msg, ca, policy_oid="1.2.3.4.1")            # la politique de l'autorité de test
    assert ts.verify(r["token"], msg, ca, "1.2.3.4.1") == r["gen_time"]
    with pytest.raises(ts.TimestampError):
        ts.stamp(srv.url, msg, ca, policy_oid="1.2.3.9.9")            # autre politique : réponse refusée
    with pytest.raises(ts.TimestampError):
        ts.verify(r["token"], msg, ca, "1.2.3.9.9")


def test_chaine_complete_via_l_application_avec_authentification(settings, authority, db, world, alert):
    srv, ca = authority
    srv.auth = "keryx:secret"
    settings.tsa_url, settings.tsa_ca_file = srv.url, ca
    settings.tsa_user, settings.tsa_password, settings.tsa_policy_oid = "keryx", "secret", "1.2.3.4.1"
    app = create_app(settings)
    a, att = attachment(app, db, world, alert)
    r = a.post(f"/api/v1/attachments/{att['id']}/timestamp")
    assert r.status_code == 201, r.text
    assert a.post(f"/api/v1/timestamps/{r.json()['id']}/verify").json()["valid"] is True
    settings.tsa_password = "faux"
    app2 = create_app(settings)
    bad = login(app2, db, "analyst_acme").post(f"/api/v1/attachments/{att['id']}/timestamp")
    assert bad.status_code == 502 and "authentification" in bad.json()["detail"]


CERTUM = __import__("pathlib").Path(__file__).parent / "data" / "certum"


@pytest.mark.skipif(not tsa.have_openssl(), reason="openssl requis")
def test_reponse_reelle_d_un_prestataire_de_l_ue_a_encodage_non_canonique():
    """Réponse RÉELLE de Certum (autorité de l'UE), enregistrée le 21/11/2026 : le décodeur strict la refuse (ensemble de
    certificats non trié), OpenSSL la valide. Keryx doit l'accepter par la vérification de secours, et refuser une altération."""
    from rfc3161_client import decode_timestamp_response
    token = (CERTUM / "resp.tsr").read_bytes()
    msg = (CERTUM / "msg.txt").read_bytes()
    ca = str(CERTUM / "ctnca.pem")
    with pytest.raises(ValueError):                              # précondition : le décodeur strict refuse bien cette réponse
        decode_timestamp_response(token)
    when = ts.verify(token, msg, ca)                             # vérifié à la date attestée (le certificat peut expirer plus tard)
    assert when.year == 2026 and when.month == 11 and when.day == 21
    assert ts.verify(token, msg, ca, policy_oid="1.2.616.1.113527.2.5.1.11") == when
    with pytest.raises(ts.TimestampError):
        ts.verify(token, msg + b"x", ca)                          # message altéré
    with pytest.raises(ts.TimestampError):
        ts.verify(token, msg, ca, policy_oid="1.2.3.9.9")         # mauvaise politique
    altered = bytearray(token)
    altered[len(altered) // 2] ^= 1
    with pytest.raises(ts.TimestampError):
        ts.verify(bytes(altered), msg, ca)                        # jeton altéré
    with pytest.raises(ts.TimestampError):
        ts.verify(token, msg, str(CERTUM.parent.parent / "tsa.py"))   # fichier d'autorité invalide


def test_autorite_reelle_de_l_ue_certum_si_reseau():
    """Essai en ligne contre Certum (KERYX_TEST_TSA_REAL_CERTUM=1) : demande, vérification de secours, revérification."""
    import os
    if not os.environ.get("KERYX_TEST_TSA_REAL_CERTUM"):
        pytest.skip("KERYX_TEST_TSA_REAL_CERTUM non défini")
    msg = ts.message_for("attachment", "essai-test-certum", "12" * 32)
    ca = str(CERTUM / "ctnca.pem")
    r = ts.stamp("http://time.certum.pl", msg, ca, policy_oid="1.2.616.1.113527.2.5.1.11")
    assert ts.verify(r["token"], msg, ca) == r["gen_time"]


def test_jeton_d_une_piece_interne_invisible_pour_le_client(stamped_app, db, world, alert):
    """Les droits sur un jeton sont ceux de la pièce : le client du même client ne lit ni ne vérifie le jeton d'une pièce
    interne, seulement celui d'une pièce qui lui est visible."""
    a, interne = attachment(stamped_app, db, world, alert)               # pièce interne (non visible par le client)
    visible = a.post("/api/v1/tickets/ACME-1/attachments", data={**REGISTRY, "visible_client": "true"},
                     files={"file": ("v.zip", zip_bytes("v.log"), "application/zip")}).json()
    t_interne = a.post(f"/api/v1/attachments/{interne['id']}/timestamp").json()["id"]
    t_visible = a.post(f"/api/v1/attachments/{visible['id']}/timestamp").json()["id"]
    c = login(stamped_app, db, "client_acme")
    assert c.get(f"/api/v1/timestamps/{t_interne}/token").status_code == 404
    assert c.post(f"/api/v1/timestamps/{t_interne}/verify").status_code == 404
    assert c.get(f"/api/v1/attachments/{interne['id']}/timestamps").status_code == 404
    assert c.get(f"/api/v1/timestamps/{t_visible}/token").status_code == 200
    assert c.post(f"/api/v1/timestamps/{t_visible}/verify").json()["valid"] is True


def test_telechargement_et_verification_de_jeton_traces(stamped_app, db, world, alert):
    from keryx.models import AuditEntry
    a, att = attachment(stamped_app, db, world, alert)
    tid = a.post(f"/api/v1/attachments/{att['id']}/timestamp").json()["id"]
    assert a.get(f"/api/v1/timestamps/{tid}/token").status_code == 200
    assert a.post(f"/api/v1/timestamps/{tid}/verify").json()["valid"] is True
    adm = login(stamped_app, db, "admin")
    cp = adm.post("/api/v1/audit/checkpoint/timestamp").json()["id"]
    assert adm.get(f"/api/v1/timestamps/{cp}/token").status_code == 200
    db.rollback()
    rows = {e.action: e for e in db.scalars(select(AuditEntry).where(AuditEntry.object_type == "timestamp"))}
    assert set(rows) == {"attachment.timestamp_download", "attachment.timestamp_verify", "audit.timestamp_download"}
    dl = rows["attachment.timestamp_download"]
    assert dl.actor == "analyst_acme" and dl.object_id == tid and dl.tenant_id == world["tenants"]["ACME"].id
    assert dl.details["object_id"] == att["id"] and rows["attachment.timestamp_verify"].details["valid"] is True
    assert rows["audit.timestamp_download"].tenant_id is None


def test_client_http_ferme_apres_la_demande(stamped_app, db, world, alert, monkeypatch):
    made, real = [], ts.make_client
    monkeypatch.setattr(ts, "make_client", lambda s: made.append(real(s)) or made[-1])
    a, att = attachment(stamped_app, db, world, alert)
    assert a.post(f"/api/v1/attachments/{att['id']}/timestamp").status_code == 201
    assert len(made) == 1 and made[0].is_closed


def test_heure_a_fractions_de_seconde_et_serie_decimale(monkeypatch, tmp_path):
    """Chemin de secours OpenSSL : une heure attestée avec fractions de seconde est acceptée, et le numéro de série est
    rendu en décimal comme par le décodeur strict (OpenSSL l'affiche en hexadécimal)."""
    import datetime as dt
    import subprocess as sp
    text = ("Status info:\nStatus: Granted.\nTST info:\nVersion: 1\nPolicy OID: 1.2.3.4.1\nHash Algorithm: sha256\n"
            "Serial number: 0x04D2\nTime stamp: Nov 21 10:11:12.345 2026 GMT\nAccuracy: 0x01 seconds\n")

    def fake(*args):
        return sp.CompletedProcess(args, 0, stdout="Verification: OK\n" if "-verify" in args else text, stderr="")

    monkeypatch.setattr(ts, "_openssl", fake)
    v = ts._openssl_verify(b"jeton", b"message", None, str(tmp_path / "ca.pem"), "1.2.3.4.1")
    assert v["gen_time"] == dt.datetime(2026, 11, 21, 10, 11, 12, tzinfo=dt.timezone.utc)
    assert v["serial"] == "1234" and v["policy"] == "1.2.3.4.1"
    assert ts._decimal_serial("Serial number: 4660\n") == "4660" and ts._decimal_serial("rien") == "?"


def test_serie_identique_par_les_deux_chemins(authority):
    """La même réponse donne le même numéro de série, que le décodeur strict ou OpenSSL l'ait lue."""
    srv, ca = authority
    msg = ts.message_for("attachment", "x", "ab" * 32)
    r = ts.stamp(srv.url, msg, ca)
    assert r["serial"].isdigit()
    assert ts._openssl_verify(r["token"], msg, None, ca, None)["serial"] == r["serial"]
    # Réponse réelle à encodage non canonique (chemin de secours seul) : série décimale aussi
    certum = ts._openssl_verify((CERTUM / "resp.tsr").read_bytes(), (CERTUM / "msg.txt").read_bytes(), None, str(CERTUM / "ctnca.pem"), None)
    assert certum["serial"].isdigit()
