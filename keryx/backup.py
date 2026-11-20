"""Sauvegarde chiffrée et restauration. [PDIS IV.3.6 sauvegardes protégées et testées ; ISO/IEC 27002 8.13]

Archive = base SQLite (copie cohérente via l'API de sauvegarde en ligne) + dossier des pièces + manifeste des
empreintes, le tout chiffré par blocs en AES-256-GCM (construction STREAM : un compteur dans le nonce et un
indicateur de dernier bloc, donc toute troncature, permutation ou modification est détectée).
La clé de chiffrement est dérivée de KERYX_SECRET_KEY (HKDF) : conserver cette clé hors de la sauvegarde.
Sauvegarde de PostgreSQL : à ajouter avec la bascule de la base (pg_dump).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sqlite3
import struct
import tarfile
import tempfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"KXBK1"
CHUNK = 1024 * 1024
TAG = 16


class BackupError(Exception):
    pass


def _key(secret_key_b64: str, salt: bytes) -> bytes:
    master = base64.b64decode(secret_key_b64)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"keryx-backup-v1").derive(master)


def _nonce(i: int, last: bool) -> bytes:
    return i.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def encrypt_stream(src, dst, secret_key_b64: str) -> None:
    salt = os.urandom(16)
    aes = AESGCM(_key(secret_key_b64, salt))
    dst.write(MAGIC + salt)
    i = 0
    buf = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        last = not nxt
        ct = aes.encrypt(_nonce(i, last), buf, MAGIC + i.to_bytes(8, "big"))
        dst.write(struct.pack(">I", len(ct)) + ct)
        if last:
            return
        buf, i = nxt, i + 1


def decrypt_stream(src, dst, secret_key_b64: str) -> None:
    head = src.read(len(MAGIC) + 16)
    if len(head) != len(MAGIC) + 16 or head[:len(MAGIC)] != MAGIC:
        raise BackupError("Fichier de sauvegarde Keryx invalide.")
    aes = AESGCM(_key(secret_key_b64, head[len(MAGIC):]))
    i, seen_last = 0, False
    while True:
        raw = src.read(4)
        if not raw:
            break
        if seen_last or len(raw) != 4:
            raise BackupError("Sauvegarde corrompue ou tronquée.")
        (n,) = struct.unpack(">I", raw)
        if not TAG <= n <= CHUNK + TAG:
            raise BackupError("Sauvegarde corrompue (taille de bloc).")
        ct = src.read(n)
        if len(ct) != n:
            raise BackupError("Sauvegarde tronquée.")
        peek = src.read(1)
        last = not peek
        if peek:
            src.seek(-1, os.SEEK_CUR)
        try:
            dst.write(aes.decrypt(_nonce(i, last), ct, MAGIC + i.to_bytes(8, "big")))
        except Exception as exc:  # InvalidTag : mauvaise clé ou archive altérée
            raise BackupError("Déchiffrement impossible : mauvaise clé ou sauvegarde altérée.") from exc
        seen_last, i = last, i + 1
    if not seen_last:
        raise BackupError("Sauvegarde vide ou tronquée.")


def _sqlite_path(url: str) -> str:
    if not url.startswith("sqlite:///"):
        raise BackupError("Seules les bases SQLite sont sauvegardées pour l'instant (PostgreSQL : pg_dump).")
    return url[len("sqlite:///"):]


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def create(database_url: str, attachments_dir: str, secret_key_b64: str, out_path: str) -> dict:
    db_path = _sqlite_path(database_url)
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "keryx.db")
        src, dst = sqlite3.connect(db_path), sqlite3.connect(snap)
        try:
            src.backup(dst)  # copie cohérente même pendant que Keryx tourne
        finally:
            dst.close(); src.close()
        files = {"keryx.db": snap}
        if os.path.isdir(attachments_dir):
            for root, _dirs, names in os.walk(attachments_dir):
                for n in names:
                    full = os.path.join(root, n)
                    files["attachments/" + os.path.relpath(full, attachments_dir).replace(os.sep, "/")] = full
        manifest = {"format": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                    "files": {name: _sha(p) for name, p in files.items()}}
        tar_path = os.path.join(tmp, "a.tar")
        with tarfile.open(tar_path, "w") as tar:
            data = json.dumps(manifest, sort_keys=True).encode()
            info = tarfile.TarInfo("manifest.json"); info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
            for name, p in files.items():
                tar.add(p, arcname=name, recursive=False)
        with open(tar_path, "rb") as s, open(out_path, "wb") as d:
            os.fchmod(d.fileno(), 0o600)
            encrypt_stream(s, d, secret_key_b64)
    return {"files": len(files), "created_at": manifest["created_at"]}


def restore(in_path: str, secret_key_b64: str, dest_dir: str) -> dict:
    """Déchiffre, vérifie les empreintes du manifeste, puis extrait dans un dossier vide."""
    if os.path.exists(dest_dir) and os.listdir(dest_dir):
        raise BackupError("Le dossier de restauration doit être vide.")
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "a.tar")
        with open(in_path, "rb") as s, open(tar_path, "wb") as d:
            decrypt_stream(s, d, secret_key_b64)
        with tarfile.open(tar_path, "r") as tar:
            tar.extractall(dest_dir, filter="data")  # refuse chemins absolus, « .. » et liens dangereux
    with open(os.path.join(dest_dir, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    for name, expected in manifest["files"].items():
        p = os.path.join(dest_dir, name)
        if not os.path.isfile(p) or _sha(p) != expected:
            raise BackupError(f"Empreinte différente après restauration : {name}")
    return {"files": len(manifest["files"]), "created_at": manifest["created_at"]}
