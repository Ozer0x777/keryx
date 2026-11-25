"""Stockage objet S3 : signature AWS v4 recoupée avec botocore, aller-retour contre un serveur S3 simulé (moto),
chiffrement avant envoi, quarantaine, destruction. [plan : stockage objet]"""
import datetime as dt
import hashlib
import socket

import boto3
import pytest
from botocore.auth import S3SigV4Auth as SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from moto.server import ThreadedMotoServer

from keryx import attachments as att
from keryx.api import create_app
from keryx.s3store import S3Store, StorageError, sign_v4

from .conftest import ALERT_SSH_BRUTEFORCE, SECRET_KEY, ingest, login
from .test_attachments import REGISTRY, zip_bytes

AK, SK, REGION = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1"
WHEN = dt.datetime(2013, 5, 24, tzinfo=dt.timezone.utc)


def botocore_headers(method, url, body):
    req = AWSRequest(method=method, url=url, data=body, headers={"x-amz-content-sha256": hashlib.sha256(body or b"").hexdigest()})
    SigV4Auth(Credentials(AK, SK), "s3", REGION).add_auth(req)
    return req.headers


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/bucket/fichiers/ab/abcdef", b""),
    ("PUT", "/bucket/keryx/quarantaine/ab/abcdef", b"contenu chiffre \x00\xff" * 50),
    ("GET", "/bucket/dossier avec espaces/été/é à.bin", b""),                   # noms non ASCII et espaces
    ("DELETE", "/bucket/a+b=c&d/~x_y-z.txt", b""),                               # caractères réservés
    ("HEAD", "/bucket", b""),
])
def test_signature_v4_identique_a_botocore(method, path, body):
    from urllib.parse import quote
    url = "http://127.0.0.1:9000" + quote(path, safe="/-_.~")
    theirs = botocore_headers(method, url, body)
    when = dt.datetime.strptime(theirs["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)   # même instant que botocore
    mine = sign_v4(method, url, {}, hashlib.sha256(body).hexdigest(), AK, SK, REGION, now=when)
    assert mine["authorization"] == theirs["Authorization"]


def test_vecteur_officiel_aws_get_object_avec_plage():
    """Exemple de la documentation AWS (GET /test.txt, Range: bytes=0-9, 24/05/2013) : signature publiée."""
    h = sign_v4("GET", "https://examplebucket.s3.amazonaws.com/test.txt", {"Range": "bytes=0-9"}, hashlib.sha256(b"").hexdigest(),
                AK, SK, REGION, now=WHEN)
    assert h["authorization"].endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_http_refuse_sauf_essai_local():
    with pytest.raises(StorageError, match="HTTPS"):
        S3Store("http://s3.local", "b", AK, SK, REGION, SECRET_KEY)
    S3Store("http://s3.local", "b", AK, SK, REGION, SECRET_KEY, allow_http=True)


@pytest.fixture(scope="module")
def moto_server():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = ThreadedMotoServer(ip_address="127.0.0.1", port=port, verbose=False)
    srv.start()
    yield f"http://127.0.0.1:{port}"
    srv.stop()


@pytest.fixture
def s3app(settings, moto_server):
    import uuid
    bucket = "keryx-" + uuid.uuid4().hex[:10]
    client = boto3.client("s3", endpoint_url=moto_server, aws_access_key_id=AK, aws_secret_access_key=SK, region_name=REGION)
    client.create_bucket(Bucket=bucket)
    settings.storage_backend, settings.s3_endpoint, settings.s3_bucket = "s3", moto_server, bucket
    settings.s3_access_key, settings.s3_secret_key, settings.s3_allow_http = AK, SK, True
    return create_app(settings), client, bucket


def objects(client, bucket):
    return [o["Key"] for o in client.list_objects_v2(Bucket=bucket).get("Contents", [])]


def test_aller_retour_chiffrement_et_destruction(s3app, db, world, alert):
    app, client, bucket = s3app
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    m = login(app, db, "manager")
    data = zip_bytes("journal.log", b"Nov 20 sshd[1]: Failed password for root\n")
    r = m.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", data, "application/zip")})
    assert r.status_code == 201, r.text
    keys = objects(client, bucket)
    assert len(keys) == 1 and keys[0].startswith("keryx/fichiers/")
    raw = client.get_object(Bucket=bucket, Key=keys[0])["Body"].read()
    assert data not in raw and b"Failed password" not in raw and len(raw) == len(data) + 12 + 16   # chiffré avant envoi
    dl = m.get(f"/api/v1/attachments/{r.json()['id']}/content", params={"motif": "analyse"})
    assert dl.status_code == 200 and dl.content == data
    # Objet déplacé sous une autre clé : le chemin est lié aux données authentifiées, le déchiffrement échoue
    client.put_object(Bucket=bucket, Key=keys[0] + "x", Body=raw)
    other = att.object_store(app.state.settings)
    with pytest.raises(StorageError):
        other.get(keys[0] + "x")
    # Objet altéré : refus propre (502), pas d'erreur 500
    client.put_object(Bucket=bucket, Key=keys[0], Body=raw[:-1] + bytes([raw[-1] ^ 1]))
    assert m.get(f"/api/v1/attachments/{r.json()['id']}/content", params={"motif": "analyse"}).status_code == 502
    client.put_object(Bucket=bucket, Key=keys[0], Body=raw)
    # Destruction (manager) : l'objet disparaît du stockage
    assert m.post(f"/api/v1/attachments/{r.json()['id']}/lifecycle", json={"lifecycle": "detruit", "reason": "fin de prestation"}).status_code == 200
    assert keys[0] not in objects(client, bucket)


def test_quarantaine_sous_son_propre_prefixe_et_etat_du_systeme(s3app, db, world, alert, monkeypatch):
    app, client, bucket = s3app
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    monkeypatch.setattr(att, "scan", lambda content, settings: ("quarantaine", "Eicar-Test"))
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", zip_bytes(), "application/zip")})
    assert r.status_code == 201
    assert [k for k in objects(client, bucket)][0].startswith("keryx/quarantaine/")
    s = login(app, db, "admin").get("/api/v1/admin/system").json()
    assert s["storage"] == "stockage objet : joignable" and s["disk_free_mb"] is None


def test_stockage_indisponible_refus_propre_sans_piece_orpheline(settings, db, world, alert, monkeypatch):
    settings.storage_backend, settings.s3_endpoint, settings.s3_bucket = "s3", "http://127.0.0.1:9", "b"
    settings.s3_access_key, settings.s3_secret_key, settings.s3_allow_http = AK, SK, True
    app = create_app(settings)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", zip_bytes(), "application/zip")})
    assert r.status_code == 502 and "indisponible" in r.json()["detail"]
    assert a.get("/api/v1/tickets/ACME-1").json()["attachments"] == []
    assert login(app, db, "admin").get("/api/v1/admin/system").json()["storage"] == "stockage objet : injoignable"


def test_configuration_incomplete(settings):
    settings.storage_backend = "s3"
    with pytest.raises(StorageError, match="incomplet"):
        att.object_store(settings)
