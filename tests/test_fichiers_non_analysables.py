"""Fichiers que l'antivirus ne peut pas analyser (PDIS IV.3.13.a) : archive chiffrée, archive chiffrée dans une
archive, archive endommagée ; statut propre, traitement de la quarantaine (jamais remis en clair au client,
téléchargé par l'équipe dans une archive chiffrée) ; chaque passage par l'antivirus journalisé (horodate, nom,
empreinte)."""
import hashlib
import io
import zipfile

import pytest
import pyzipper
from sqlalchemy import select

from keryx import attachments as att
from keryx.models import Attachment, AuditEntry

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login
from .test_attachments import REGISTRY


def _zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, c in entries.items():
            z.writestr(n, c)
    return buf.getvalue()


def _chiffre() -> bytes:
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("charge.exe", b"MZ" + b"\x00" * 64)
    return buf.getvalue()


def test_detection():
    assert att.non_analysable(_zip({"auth.log": b"ok"}), "fichier") is None
    assert att.non_analysable(_chiffre(), "fichier") == "archive chiffrée"
    imbrique = att.non_analysable(_zip({"dedans.zip": _chiffre()}), "fichier")
    assert imbrique.startswith("archive chiffrée") and "dedans.zip" in imbrique
    abime = bytearray(_zip({"a.txt": b"x" * 1000}))
    abime[40:60] = b"\xff" * 20
    assert att.non_analysable(bytes(abime), "fichier") in ("archive endommagée", "archive illisible")
    assert att.non_analysable(b"\x89PNG...", "image") is None


@pytest.fixture
def ticket(app, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    return "ACME-1"


def _deposer(c, data, name):
    form = {**REGISTRY, "visible_client": "true"}
    return c.post("/api/v1/tickets/ACME-1/attachments", data=form, files={"file": (name, data, "application/zip")})


def test_archive_chiffree_isolee_et_journalisee(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    data = _chiffre()
    r = _deposer(a, data, "chiffre.zip")
    assert r.status_code == 201, r.text
    db.rollback()
    piece = db.scalars(select(Attachment)).one()
    assert piece.scan_status == "non_analysable" and piece.scan_detail == "archive chiffrée"
    e = db.scalars(select(AuditEntry).where(AuditEntry.action == "antivirus.analyse")).one()
    assert e.details == {"fichier": "chiffre.zip", "sha256": hashlib.sha256(data).hexdigest(),
                         "resultat": "non_analysable", "detail": "archive chiffrée"} and e.ts
    # stockée avec les pièces en quarantaine, jamais remise au client, remise à l'équipe dans une archive chiffrée
    assert att.read(app.state.settings, piece.storage_name, True)
    c = login(app, db, "client_acme")
    assert c.get(f"/api/v1/attachments/{piece.id}/content", headers={"X-CSRF-Token": c.cookies.get("keryx_csrf")}).status_code in (403, 404)
    sans = a.get(f"/api/v1/attachments/{piece.id}/content", params={"motif": "analyse hors ligne"},
                 headers={"X-CSRF-Token": a.cookies.get("keryx_csrf")})
    assert sans.status_code == 409 and "impossible à analyser" in sans.json()["detail"]   # confirmation explicite exigée
    dl = a.get(f"/api/v1/attachments/{piece.id}/content", params={"motif": "analyse hors ligne", "confirmer_malveillant": "true"},
               headers={"X-CSRF-Token": a.cookies.get("keryx_csrf")})
    assert dl.status_code == 200 and dl.content != data             # jamais le contenu en clair
    assert zipfile.ZipFile(io.BytesIO(dl.content)).infolist()[0].flag_bits & 0x1      # archive chiffrée de quarantaine


def test_archive_saine_journalisee(app, db, world, ticket):
    a = login(app, db, "analyst_acme")
    assert _deposer(a, _zip({"auth.log": b"Nov 20 sshd"}), "preuve.zip").status_code == 201
    db.rollback()
    assert db.scalars(select(Attachment)).one().scan_status == "non_analyse"        # pas d'antivirus en test
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "antivirus.analyse")).one().details["resultat"] == "non_analyse"
