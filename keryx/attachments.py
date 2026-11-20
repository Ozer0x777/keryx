"""Pièces jointes et preuves.

[PRIS VI.5.3.c] registre de collecte : description, date/heure, méthode, sensibilité ;
[PRIS VI.2.4] conservation / restitution / destruction tracées ;
[PRIS IV.3.q] codes malveillants : jamais supprimés, isolés, jamais servis au client ;
[ISO/IEC 27037, RFC 3227] intégrité (SHA-256) et chaîne de possession.
Règles : 20 Mo maximum, archives jamais décompressées, stockage hors racine web sous nom aléatoire,
images ré-encodées (métadonnées supprimées), SVG refusé.
"""
from __future__ import annotations

import hashlib
import io
import os
import socket
import struct
import warnings
from dataclasses import dataclass

from PIL import Image

from .config import Settings
from .ids import uuid7

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
IMAGE_FORMATS = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
MAX_IMAGE_PIXELS = 40_000_000


class AttachmentRejected(ValueError):
    pass


@dataclass
class Prepared:
    kind: str            # fichier | image
    content: bytes       # octets à stocker
    content_type: str
    sha256: str          # empreinte des octets stockés
    original_sha256: str  # empreinte des octets reçus


def sniff(data: bytes) -> str:
    if data.startswith(ZIP_MAGIC):
        return "zip"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return "inconnu"


def _reencode_image(data: bytes) -> tuple[bytes, str]:
    """Décode puis ré-encode l'image : supprime EXIF et toute donnée cachée après l'image."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            img = Image.open(io.BytesIO(data))
            fmt = img.format
            if fmt not in IMAGE_FORMATS:
                raise AttachmentRejected("Format d'image non accepté (PNG, JPEG ou WebP).")
            if img.width * img.height > MAX_IMAGE_PIXELS:
                raise AttachmentRejected("Image trop grande.")
            img.load()
        except (Image.DecompressionBombWarning, Image.DecompressionBombError) as exc:
            raise AttachmentRejected("Image trop grande.") from exc
        except AttachmentRejected:
            raise
        except Exception as exc:  # Pillow lève des exceptions variées sur un fichier corrompu
            raise AttachmentRejected("Image illisible ou corrompue.") from exc
    out = io.BytesIO()
    if fmt == "JPEG":
        img.convert("RGB").save(out, format="JPEG", quality=90)
    elif fmt == "PNG":
        clean = img.convert("RGBA") if img.mode in ("P", "LA", "RGBA") else img.convert("RGB")
        clean.save(out, format="PNG")
    else:
        img.convert("RGBA").save(out, format="WEBP", quality=90)
    return out.getvalue(), IMAGE_FORMATS[fmt]


def prepare(data: bytes, settings: Settings) -> Prepared:
    if not data:
        raise AttachmentRejected("Fichier vide.")
    if len(data) > settings.max_attachment_bytes:
        raise AttachmentRejected("Fichier trop volumineux (20 Mo maximum) : déclarer une preuve externe.")
    original = hashlib.sha256(data).hexdigest()
    kind = sniff(data)
    if kind == "zip":
        return Prepared("fichier", data, "application/zip", original, original)
    if kind in ("png", "jpeg", "webp"):
        content, ctype = _reencode_image(data)
        return Prepared("image", content, ctype, hashlib.sha256(content).hexdigest(), original)
    raise AttachmentRejected("Type de fichier non accepté : archive ZIP, PNG, JPEG ou WebP uniquement.")


# ---------------------------------------------------------------- antivirus (clamd, protocole INSTREAM)
def scan(data: bytes, settings: Settings) -> tuple[str, str | None]:
    """Renvoie (statut, détail). Sans ClamAV configuré ou en cas d'erreur : « non_analyse »."""
    if not settings.clamav_host:
        return "non_analyse", "ClamAV non configuré"
    try:
        with socket.create_connection((settings.clamav_host, settings.clamav_port), timeout=30) as s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 64 * 1024):
                chunk = data[i:i + 64 * 1024]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            reply = b""
            while not reply.endswith(b"\0"):
                part = s.recv(4096)
                if not part:
                    break
                reply += part
    except OSError as exc:
        return "non_analyse", f"ClamAV injoignable ({type(exc).__name__})"
    text = reply.rstrip(b"\0").decode("utf-8", "replace")
    if text.endswith("OK"):
        return "sain", None
    if text.endswith("FOUND"):
        return "quarantaine", text.split(":", 1)[-1].replace("FOUND", "").strip()[:200]
    return "non_analyse", f"Réponse ClamAV inattendue : {text[:100]}"


# ---------------------------------------------------------------- stockage
def _path(settings: Settings, storage_name: str, quarantined: bool) -> str:
    sub = "quarantaine" if quarantined else "fichiers"
    return os.path.join(settings.attachments_dir, sub, storage_name[:2], storage_name)


def store(settings: Settings, content: bytes, quarantined: bool) -> str:
    storage_name = uuid7().replace("-", "")
    path = _path(settings, storage_name, quarantined)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return storage_name


def read(settings: Settings, storage_name: str, quarantined: bool) -> bytes:
    with open(_path(settings, storage_name, quarantined), "rb") as f:
        return f.read()


def destroy(settings: Settings, storage_name: str, quarantined: bool) -> None:
    path = _path(settings, storage_name, quarantined)
    if os.path.exists(path):
        os.remove(path)


def safe_filename(name: str) -> str:
    name = os.path.basename((name or "fichier").replace("\\", "/"))
    cleaned = "".join(c for c in name if c.isprintable() and c not in '"<>:|?*;')
    return (cleaned or "fichier")[:200]
