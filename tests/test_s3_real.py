"""Stockage objet contre un VRAI serveur S3 qui vérifie les signatures (testé avec Garage 1.0.1).
Exécuté seulement si KERYX_TEST_S3_REAL est défini : « endpoint|bucket|access_key|secret_key|region »."""
import os
import uuid

import pytest

from keryx.api import create_app
from keryx.s3store import S3Store, StorageError

from .conftest import ALERT_SSH_BRUTEFORCE, SECRET_KEY, ingest, login
from .test_attachments import REGISTRY, zip_bytes

REAL = os.environ.get("KERYX_TEST_S3_REAL")
pytestmark = pytest.mark.skipif(not REAL, reason="KERYX_TEST_S3_REAL non défini (serveur S3 réel requis)")


def conf():
    endpoint, bucket, ak, sk, region = REAL.split("|")
    return endpoint, bucket, ak, sk, region


def store(**over):
    endpoint, bucket, ak, sk, region = conf()
    kw = dict(endpoint=endpoint, bucket=bucket, access_key=ak, secret_key=sk, region=region, master_key_b64=SECRET_KEY,
              prefix="t-" + uuid.uuid4().hex[:8], allow_http=True)
    kw.update(over)
    return S3Store(**kw)


def test_aller_retour_signatures_acceptees_par_le_serveur():
    s = store()
    assert s.ping() is True
    for name in ("simple", "avec espaces et été", "a+b=c&d", "~x_y-z.bin"):
        key = s.key_for("fichiers", name)
        payload = os.urandom(1500) + name.encode()
        s.put(key, payload)
        assert s.get(key) == payload
        s.delete(key)
        with pytest.raises(FileNotFoundError):
            s.get(key)
    s.delete(s.key_for("fichiers", "jamais-existe"))            # supprimer l'inexistant : sans erreur


def test_mauvaise_signature_refusee_par_le_serveur():
    bad = store(secret_key="x" * 64)
    assert bad.ping() is False
    with pytest.raises(StorageError, match="refus"):
        bad.put(bad.key_for("fichiers", "x"), b"contenu")
    with pytest.raises(StorageError):
        store(access_key="GKinexistant").get("quelque/chose")


def test_pieces_via_l_application_sur_serveur_reel(settings, db, world, alert):
    endpoint, bucket, ak, sk, region = conf()
    settings.storage_backend, settings.s3_endpoint, settings.s3_bucket = "s3", endpoint, bucket
    settings.s3_access_key, settings.s3_secret_key, settings.s3_region = ak, sk, region
    settings.s3_allow_http, settings.s3_prefix = True, "app-" + uuid.uuid4().hex[:8]
    app = create_app(settings)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    m = login(app, db, "manager")
    data = zip_bytes("journal.log", b"Failed password for root\n" * 40)
    r = m.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", data, "application/zip")})
    assert r.status_code == 201, r.text
    dl = m.get(f"/api/v1/attachments/{r.json()['id']}/content", params={"motif": "analyse"})
    assert dl.status_code == 200 and dl.content == data
    assert m.post(f"/api/v1/attachments/{r.json()['id']}/lifecycle", json={"lifecycle": "detruit", "reason": "fin de prestation"}).status_code == 200
    assert login(app, db, "admin").get("/api/v1/admin/system").json()["storage"] == "stockage objet : joignable"
