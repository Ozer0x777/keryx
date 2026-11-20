"""Sauvegarde chiffrée et restauration. [PDIS IV.3.6 : sauvegardes protégées et testées]"""
import io
import os

import pytest
from sqlalchemy import select

from keryx import audit, backup, security
from keryx.cli import main as cli_main
from keryx.db import make_engine, make_session_factory
from keryx.models import Attachment, Ticket

from .conftest import ALERT_SSH_BRUTEFORCE, SECRET_KEY, ingest, login
from .test_attachments import REGISTRY, zip_bytes


def populate(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", zip_bytes(), "application/zip")})
    assert r.status_code == 201
    return r.json()["sha256"]


def test_aller_retour_complet(app, db, world, alert, settings, tmp_path):
    sha = populate(app, db, world, alert)
    out = tmp_path / "sauvegarde.kxb"
    info = backup.create(settings.database_url, settings.attachments_dir, SECRET_KEY, str(out))
    assert info["files"] >= 2 and os.stat(out).st_mode & 0o777 == 0o600
    raw = out.read_bytes()
    assert b"SQLite format" not in raw and b"ACME" not in raw and sha.encode() not in raw   # rien en clair
    dest = tmp_path / "restauration"
    backup.restore(str(out), SECRET_KEY, str(dest))
    audit.configure(SECRET_KEY)
    rdb = make_session_factory(make_engine(f"sqlite:///{dest}/keryx.db"))()
    assert rdb.scalars(select(Ticket)).one().ref == "ACME-1"
    att = rdb.scalars(select(Attachment)).one()
    assert att.sha256 == sha
    stored = dest / "attachments" / "fichiers" / att.storage_name[:2] / att.storage_name
    assert stored.exists()
    assert audit.verify_chain(rdb) == (True, None)


def test_mauvaise_cle_alteration_et_troncature(app, db, world, alert, settings, tmp_path):
    populate(app, db, world, alert)
    out = tmp_path / "s.kxb"
    backup.create(settings.database_url, settings.attachments_dir, SECRET_KEY, str(out))
    with pytest.raises(backup.BackupError):
        backup.restore(str(out), security.new_secret_key(), str(tmp_path / "r1"))
    data = bytearray(out.read_bytes())
    data[len(data) // 2] ^= 0x01
    bad = tmp_path / "alteree.kxb"; bad.write_bytes(bytes(data))
    with pytest.raises(backup.BackupError):
        backup.restore(str(bad), SECRET_KEY, str(tmp_path / "r2"))
    cut = tmp_path / "tronquee.kxb"; cut.write_bytes(out.read_bytes()[:-40])
    with pytest.raises(backup.BackupError):
        backup.restore(str(cut), SECRET_KEY, str(tmp_path / "r3"))
    junk = tmp_path / "x.kxb"; junk.write_bytes(b"pas une sauvegarde")
    with pytest.raises(backup.BackupError):
        backup.restore(str(junk), SECRET_KEY, str(tmp_path / "r4"))
    (tmp_path / "plein").mkdir(); (tmp_path / "plein" / "x").write_text("x")
    with pytest.raises(backup.BackupError):
        backup.restore(str(out), SECRET_KEY, str(tmp_path / "plein"))


def test_flux_multi_blocs_et_blocs_permutes():
    payload = os.urandom(backup.CHUNK * 2 + 123)
    enc = io.BytesIO(); backup.encrypt_stream(io.BytesIO(payload), enc, SECRET_KEY)
    out = io.BytesIO(); backup.decrypt_stream(io.BytesIO(enc.getvalue()), out, SECRET_KEY)
    assert out.getvalue() == payload
    # Supprimer le dernier bloc (troncature « propre » à une frontière) est détecté
    raw = enc.getvalue()
    head, body = raw[:21], raw[21:]
    blocks, pos = [], 0
    while pos < len(body):
        n = int.from_bytes(body[pos:pos + 4], "big"); blocks.append(body[pos:pos + 4 + n]); pos += 4 + n
    assert len(blocks) == 3
    with pytest.raises(backup.BackupError):
        backup.decrypt_stream(io.BytesIO(head + b"".join(blocks[:2])), io.BytesIO(), SECRET_KEY)
    with pytest.raises(backup.BackupError):
        backup.decrypt_stream(io.BytesIO(head + blocks[1] + blocks[0] + blocks[2]), io.BytesIO(), SECRET_KEY)


def test_commandes_cli(app, db, world, alert, settings, tmp_path, monkeypatch, capsys):
    populate(app, db, world, alert)
    monkeypatch.setenv("KERYX_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KERYX_SECRET_KEY", SECRET_KEY)
    monkeypatch.setenv("KERYX_ATTACHMENTS_DIR", settings.attachments_dir)
    out = str(tmp_path / "cli.kxb")
    assert cli_main(["backup", out]) == 0
    assert cli_main(["restore", out, "--to", str(tmp_path / "rest")]) == 0
    assert "Chaîne d'audit intègre" in capsys.readouterr().out
    assert cli_main(["restore", out, "--to", str(tmp_path / "rest")]) == 2   # dossier non vide
