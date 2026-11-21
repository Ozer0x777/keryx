"""Outils d'aide au choix de production : migration des pièces vers S3 et essai d'une autorité d'horodatage."""
import socket

import boto3
import pytest
from moto.server import ThreadedMotoServer

from keryx.cli import main as cli_main

from . import tsa
from .conftest import ALERT_SSH_BRUTEFORCE, SECRET_KEY, ingest, login
from .test_attachments import REGISTRY, zip_bytes
from .test_s3 import AK, REGION, SK


@pytest.fixture(scope="module")
def moto():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
    srv.start()
    yield f"http://127.0.0.1:{port}"
    srv.stop()


def test_migration_des_pieces_du_disque_vers_s3(app, db, world, alert, settings, tmp_path, monkeypatch, moto, capsys):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    originals = {}
    for i in range(3):
        data = zip_bytes(f"journal{i}.log", f"ligne {i}\n".encode() * 100)
        r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": (f"p{i}.zip", data, "application/zip")})
        assert r.status_code == 201
        originals[r.json()["id"]] = data
    client = boto3.client("s3", endpoint_url=moto, aws_access_key_id=AK, aws_secret_access_key=SK, region_name=REGION)
    client.create_bucket(Bucket="migration")
    for k, v in {"KERYX_DATABASE_URL": settings.database_url, "KERYX_SECRET_KEY": SECRET_KEY, "KERYX_ATTACHMENTS_DIR": settings.attachments_dir,
                 "KERYX_STORAGE": "s3", "KERYX_S3_ENDPOINT": moto, "KERYX_S3_BUCKET": "migration", "KERYX_S3_ACCESS_KEY": AK,
                 "KERYX_S3_SECRET_KEY": SK, "KERYX_S3_REGION": REGION, "KERYX_S3_ALLOW_HTTP": "true"}.items():
        monkeypatch.setenv(k, v)
    db.rollback()
    assert cli_main(["migrate-attachments", "--dry-run"]) == 0
    assert "3 pièce(s) copiée(s) (simulation)" in capsys.readouterr().out
    assert client.list_objects_v2(Bucket="migration").get("KeyCount", 0) == 0                  # simulation : rien n'est écrit
    assert cli_main(["migrate-attachments"]) == 0
    assert "3 pièce(s) copiée(s) et relue(s)" in capsys.readouterr().out
    assert client.list_objects_v2(Bucket="migration")["KeyCount"] == 3
    # Les pièces se lisent maintenant depuis le stockage objet (les fichiers du disque restent en place)
    from keryx.api import create_app
    from keryx.config import Settings
    s3 = Settings(database_url=settings.database_url, secret_key=SECRET_KEY, cookie_secure=False, attachments_dir=str(tmp_path / "vide"),
                  web_dist=str(tmp_path / "x"), public_url="https://keryx.local", storage_backend="s3", s3_endpoint=moto,
                  s3_bucket="migration", s3_access_key=AK, s3_secret_key=SK, s3_region=REGION, s3_allow_http=True)
    app2 = create_app(s3)
    m = login(app2, db, "manager")
    for att_id, data in originals.items():
        assert m.get(f"/api/v1/attachments/{att_id}/content", params={"motif": "essai"}).content == data
    db.rollback()                                                                              # fin du snapshot de lecture
    assert cli_main(["migrate-attachments"]) == 0                                               # rejouable sans dégât


def test_migration_exige_la_configuration_s3(settings, monkeypatch, capsys):
    monkeypatch.setenv("KERYX_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KERYX_SECRET_KEY", SECRET_KEY)
    monkeypatch.setenv("KERYX_STORAGE", "disk")
    assert cli_main(["migrate-attachments"]) == 2


@pytest.mark.skipif(not tsa.have_openssl(), reason="openssl requis")
def test_tsa_check(settings, tmp_path, monkeypatch, capsys):
    d = tmp_path / "tsa"; d.mkdir()
    ca = tsa.make_pki(d); srv = tsa.Tsa(d); srv.auth = "u:p"
    try:
        for k, v in {"KERYX_DATABASE_URL": settings.database_url, "KERYX_SECRET_KEY": SECRET_KEY, "KERYX_TSA_URL": srv.url, "KERYX_TSA_CA_FILE": ca}.items():
            monkeypatch.setenv(k, v)
        assert cli_main(["tsa-check"]) == 1 and "authentification" in capsys.readouterr().err
        monkeypatch.setenv("KERYX_TSA_USER", "u"); monkeypatch.setenv("KERYX_TSA_PASSWORD", "p")
        assert cli_main(["tsa-check"]) == 0
        out = capsys.readouterr().out
        assert "OK : horodatage obtenu et vérifié" in out and "Politique (OID)" in out and "KERYX_TSA_POLICY_OID" in out
        monkeypatch.setenv("KERYX_TSA_POLICY_OID", "1.2.3.9.9")
        assert cli_main(["tsa-check"]) == 1
    finally:
        srv.stop()
