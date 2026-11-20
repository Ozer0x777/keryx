"""Pièces jointes et preuves. [PRIS VI.5.3.c, VI.2.4, IV.3.q ; ISO/IEC 27037 ; RFC 3227]"""
import hashlib
import io
import socket
import struct
import threading
import zipfile

import pytest
from PIL import Image
from sqlalchemy import select

from keryx.api import create_app
from keryx.models import Attachment, CustodyEvent

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
REGISTRY = {"description": "Journaux d'authentification du serveur", "collected_at": "2026-11-20T14:50:00Z",
            "method": "Export /var/log/auth.log via l'agent", "sensitivity": "TLP:AMBER"}


def zip_bytes(name="auth.log", content=b"Nov 20 sshd failed\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, content)
    return buf.getvalue()


def png_with_exif() -> bytes:
    img = Image.new("RGB", (40, 20), (200, 30, 30))
    exif = Image.Exif()
    exif[0x010F] = "AppareilSecret"  # Make
    buf = io.BytesIO()
    img.save(buf, format="PNG", exif=exif)
    return buf.getvalue() + b"DONNEES-CACHEES-APRES-IEND"


def upload(c, data, name="preuve.zip", **extra):
    form = {**REGISTRY, **extra}
    return c.post("/api/v1/tickets/ACME-1/attachments", data=form, files={"file": (name, data, "application/octet-stream")})


@pytest.fixture
def ticket(app, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    return "ACME-1"


def test_depot_zip_registre_et_empreinte(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    data = zip_bytes()
    r = upload(a, data)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["sha256"] == hashlib.sha256(data).hexdigest()
    assert body["method"].startswith("Export") and body["sensitivity"] == "TLP:AMBER"
    assert body["scan_status"] == "non_analyse"  # pas de ClamAV en test : jamais présenté comme sain
    row = db.scalars(select(Attachment)).one()
    assert row.storage_name and row.storage_name not in row.filename  # nom aléatoire sur disque
    # L'archive n'est jamais décompressée : le fichier stocké est identique à l'envoi
    dl = a.get(f"/api/v1/attachments/{row.id}/content", params={"motif": "analyse"})
    assert dl.content == data and dl.headers["content-disposition"].startswith("attachment")
    db.rollback()  # nouvel instantané de lecture
    actions = [e.action for e in db.scalars(select(CustodyEvent).order_by(CustodyEvent.ts))]
    assert actions == ["depot", "telechargement"]


def test_registre_de_collecte_obligatoire(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/attachments", data={"description": "x"},
               files={"file": ("p.zip", zip_bytes(), "application/zip")})
    assert r.status_code == 422


def test_telechargement_exige_un_motif(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    att_id = upload(a, zip_bytes()).json()["id"]
    assert a.get(f"/api/v1/attachments/{att_id}/content").status_code == 422


def test_types_refuses(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    assert upload(a, svg, name="x.svg").status_code == 422
    assert upload(a, b"MZ\x90\x00 binaire", name="x.exe").status_code == 422


def test_taille_maximale(app, db, world, ticket, settings):
    a = login(app, db, "analyst_acme")
    big = b"PK\x03\x04" + b"0" * settings.max_attachment_bytes
    assert upload(a, big).status_code == 413


def test_image_reencodee_sans_metadonnees(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    data = png_with_exif()
    r = upload(a, data, name="capture.png")
    assert r.status_code == 201 and r.json()["kind"] == "image"
    att_id = r.json()["id"]
    stored = a.get(f"/api/v1/attachments/{att_id}/content").content
    assert b"AppareilSecret" not in stored and b"DONNEES-CACHEES" not in stored
    assert Image.open(io.BytesIO(stored)).size == (40, 20)


def test_client_depose_et_ne_voit_que_ses_pieces(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    upload(a, zip_bytes(), name="interne.zip")  # non visible client par défaut
    cl = login(app, db, "client_acme")
    r = upload(cl, zip_bytes(), name="client.zip")
    assert r.status_code == 201 and r.json()["visible_client"] is True
    names = [x["filename"] for x in cl.get("/api/v1/tickets/ACME-1").json()["attachments"]]
    assert names == ["client.zip"]


def test_autre_client_ne_peut_pas_lire_une_piece(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    att_id = upload(a, zip_bytes()).json()["id"]
    other = login(app, db, "analyst_delta")
    assert other.get(f"/api/v1/attachments/{att_id}/content", params={"motif": "x" * 5}).status_code == 404


def test_preuve_externe(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/preuves-externes", json={
        "description": "Image mémoire de srv-web-01", "collected_at": "2026-11-20T15:02:00Z",
        "method": "Acquisition RAM (outil validé)", "sha256": "a" * 64, "location": "Coffre hors ligne n°2",
        "size": 17179869184, "filename": "srv-web-01.mem"})
    assert r.status_code == 201 and r.json()["kind"] == "preuve_externe"
    assert a.get(f"/api/v1/attachments/{r.json()['id']}/content").status_code == 410


def test_cycle_de_vie_restitution_et_destruction(app, db, world, ticket, settings):
    a = login(app, db, "analyst_acme")
    att_id = upload(a, zip_bytes()).json()["id"]
    # Destruction réservée au manager
    assert a.post(f"/api/v1/attachments/{att_id}/lifecycle",
                  json={"lifecycle": "detruit", "reason": "fin de prestation"}).status_code == 403
    m = login(app, db, "manager")
    r = m.post(f"/api/v1/attachments/{att_id}/lifecycle", json={"lifecycle": "detruit", "reason": "fin de prestation"})
    assert r.status_code == 200 and r.json()["lifecycle"] == "detruit"
    assert a.get(f"/api/v1/attachments/{att_id}/content", params={"motif": "x" * 5}).status_code == 410
    custody = m.get(f"/api/v1/attachments/{att_id}/custody").json()["items"]
    assert [c["action"] for c in custody][-1] == "detruit"
    row = db.get(Attachment, att_id)
    assert row.sha256  # le registre et l'empreinte restent après destruction


def _fake_clamd(reply: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def run():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                buf = b""
                while not buf.startswith(b"zINSTREAM\0"):
                    buf += conn.recv(4096)
                buf = buf[len(b"zINSTREAM\0"):]
                while True:
                    while len(buf) < 4:
                        buf += conn.recv(65536)
                    size = struct.unpack(">I", buf[:4])[0]
                    buf = buf[4:]
                    if size == 0:
                        break
                    while len(buf) < size:
                        buf += conn.recv(65536)
                    buf = buf[size:]
                conn.sendall(reply)

    threading.Thread(target=run, daemon=True).start()
    return srv


def test_malware_en_quarantaine_jamais_supprime(settings, db, request):
    clamd = _fake_clamd(b"stream: Eicar-Test-Signature FOUND\0")
    settings.clamav_host, settings.clamav_port = "127.0.0.1", clamd.getsockname()[1]
    app = create_app(settings)
    world = request.getfixturevalue("world")
    ingest(app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    a = login(app, db, "analyst_acme")
    r = upload(a, zip_bytes("eicar.com", EICAR), visible_client="true")
    assert r.status_code == 201 and r.json()["scan_status"] == "quarantaine"
    att_id = r.json()["id"]
    # Analyste : confirmation + motif obligatoires, servi en octet-stream sous un nom explicite
    assert a.get(f"/api/v1/attachments/{att_id}/content", params={"motif": "analyse"}).status_code == 409
    dl = a.get(f"/api/v1/attachments/{att_id}/content", params={"motif": "analyse", "confirmer_malveillant": "true"})
    assert dl.status_code == 200 and ".quarantaine" in dl.headers["content-disposition"]
    assert dl.headers["content-type"] == "application/octet-stream"
    # Client : jamais, même si la pièce lui était visible
    cl = login(app, db, "client_acme")
    assert cl.get(f"/api/v1/attachments/{att_id}/content",
                  params={"motif": "x" * 5, "confirmer_malveillant": "true"}).status_code == 404
    clamd.close()


def test_fichier_sain_selon_clamav(settings, db, request):
    clamd = _fake_clamd(b"stream: OK\0")
    settings.clamav_host, settings.clamav_port = "127.0.0.1", clamd.getsockname()[1]
    app = create_app(settings)
    world = request.getfixturevalue("world")
    ingest(app, world["keys"]["ACME"], ALERT_SSH_BRUTEFORCE)
    a = login(app, db, "analyst_acme")
    assert upload(a, zip_bytes()).json()["scan_status"] == "sain"
    clamd.close()
