"""Authentification et secrets : Argon2id, TOTP, codes de secours, clés d'API, chiffrement au repos.

[RFC 9106] Argon2id. [RFC 6238 / 4226] TOTP. [PDIS IV.3.9.d] authentification forte.
[ASVS 5.0 V6 authentification, V7 session, V11 cryptographie]. [RGS B1] AES-256-GCM.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ph = PasswordHasher()  # profil RFC 9106 « bas-mémoire » (t=3, m=64 Mio, p=4)
# Empreinte factice : vérifiée quand l'identifiant n'existe pas, pour un temps de réponse identique.
_DUMMY_HASH = _ph.hash("keryx-dummy-password-for-timing")

RECOVERY_CODE_COUNT = 10


# ---------------------------------------------------------------- mots de passe
def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Le mot de passe doit contenir au moins 12 caractères.")
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _ph.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ---------------------------------------------------------------- chiffrement des secrets au repos
class SecretBox:
    """AES-256-GCM. Format stocké : « v1: » + base64(nonce 12 octets + chiffré + tag)."""

    def __init__(self, key_b64: str | None):
        if not key_b64:
            raise RuntimeError("KERYX_SECRET_KEY manquante (32 octets en base64 : `python -m keryx.cli gen-key`).")
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise RuntimeError("KERYX_SECRET_KEY doit faire 32 octets une fois décodée.")
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return "v1:" + base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, token: str, context: str) -> str:
        if not token.startswith("v1:"):
            raise ValueError("Format de secret inconnu.")
        raw = base64.b64decode(token[3:])
        return self._aes.decrypt(raw[:12], raw[12:], context.encode("utf-8")).decode("utf-8")


def new_secret_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


# ---------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Keryx")


def verify_totp(secret: str, code: str, last_step: int | None) -> int | None:
    """Vérifie le code (fenêtre ±1 pas de 30 s). Renvoie le pas utilisé, ou None.
    Un pas déjà utilisé, ou antérieur, est refusé (anti-rejeu)."""
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """Renvoie (codes en clair à montrer une seule fois, empreintes à stocker)."""
    plain = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_CODE_COUNT)]
    return plain, [_ph.hash(c) for c in plain]


def use_recovery_code(hashes: list[str], code: str) -> list[str] | None:
    """Si le code correspond, renvoie la liste privée de ce code (usage unique)."""
    for i, h in enumerate(hashes):
        try:
            if _ph.verify(h, (code or "").strip().lower()):
                return hashes[:i] + hashes[i + 1:]
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            continue
    return None


# ---------------------------------------------------------------- jetons
def new_api_key() -> tuple[str, str, str]:
    """Renvoie (clé en clair, préfixe affichable, empreinte SHA-256 stockée)."""
    key = "kx_" + secrets.token_urlsafe(32)
    return key, key[:10], sha256(key)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hmac_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
