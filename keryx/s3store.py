"""Stockage objet compatible S3 (MinIO, Garage, Scaleway, OVHcloud…) pour les pièces jointes. [plan : stockage objet]

Client minimal (PUT, GET, DELETE, HEAD) avec signature AWS Signature Version 4, sans dépendance supplémentaire.
Les objets sont chiffrés AVANT envoi (AES-256-GCM, clé dérivée de KERYX_SECRET_KEY, chemin de l'objet lié aux données
authentifiées) : le serveur d'objets ne voit jamais le contenu des pièces, et un objet déplacé ne se déchiffre pas.
L'adresse du serveur doit être en HTTPS (HTTP seulement avec KERYX_S3_ALLOW_HTTP, essais locaux).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import os
from urllib.parse import quote, urlparse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HTTP_TIMEOUT = 30.0
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class StorageError(Exception):
    pass


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign_v4(method: str, url: str, headers: dict, payload_hash: str, access_key: str, secret_key: str,
            region: str, now: dt.datetime | None = None, service: str = "s3") -> dict:
    """Renvoie les en-têtes à envoyer (dont Authorization), selon AWS Signature Version 4."""
    now = now or dt.datetime.now(dt.timezone.utc)
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    u = urlparse(url)
    hdrs = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    hdrs.update({"host": u.netloc, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date})
    names = sorted(hdrs)
    canonical_query = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted(
        (kv.split("=", 1) if "=" in kv else (kv, "")) for kv in u.query.split("&") if kv)) if u.query else ""
    canonical = "\n".join([method, u.path or "/", canonical_query,
                           "".join(f"{n}:{hdrs[n]}\n" for n in names), ";".join(names), payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), date), region), service), "aws4_request")
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    hdrs["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={';'.join(names)}, "
                             f"Signature={signature}")
    return hdrs


class S3Store:
    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str, region: str, master_key_b64: str,
                 prefix: str = "", allow_http: bool = False, http: httpx.Client | None = None):
        u = urlparse(endpoint)
        if u.scheme != "https" and not (allow_http and u.scheme == "http"):
            raise StorageError("L'adresse du stockage objet doit être en HTTPS.")
        self.endpoint, self.bucket, self.region = endpoint.rstrip("/"), bucket, region
        self.access_key, self.secret_key, self.prefix = access_key, secret_key, prefix.strip("/")
        self.http = http or httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False)
        self._aes = AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"keryx-object-store-v1")
                           .derive(base64.b64decode(master_key_b64)))

    def key_for(self, sub: str, name: str) -> str:
        return "/".join(p for p in (self.prefix, sub, name[:2], name) if p)

    def _url(self, key: str = "") -> str:
        return f"{self.endpoint}/{quote(self.bucket)}" + (f"/{quote(key, safe='/-_.~')}" if key else "")

    def _request(self, method: str, key: str, body: bytes = b"") -> httpx.Response:
        url = self._url(key)
        headers = sign_v4(method, url, {}, hashlib.sha256(body).hexdigest() if body else EMPTY_SHA256,
                          self.access_key, self.secret_key, self.region)
        try:
            return self.http.request(method, url, content=body or None, headers=headers)
        except httpx.HTTPError as exc:
            raise StorageError("Stockage objet injoignable.") from exc

    def put(self, key: str, content: bytes) -> None:
        nonce = os.urandom(12)
        blob = nonce + self._aes.encrypt(nonce, content, key.encode())
        r = self._request("PUT", key, blob)
        if r.status_code not in (200, 201):
            raise StorageError(f"Écriture refusée par le stockage objet ({r.status_code}).")

    def get(self, key: str) -> bytes:
        r = self._request("GET", key)
        if r.status_code == 404:
            raise FileNotFoundError(key)
        if r.status_code != 200:
            raise StorageError(f"Lecture refusée par le stockage objet ({r.status_code}).")
        try:
            return self._aes.decrypt(r.content[:12], r.content[12:], key.encode())
        except Exception as exc:  # InvalidTag : objet altéré ou déplacé
            raise StorageError("Objet corrompu ou déplacé : déchiffrement impossible.") from exc

    def delete(self, key: str) -> None:
        r = self._request("DELETE", key)
        if r.status_code not in (200, 204, 404):
            raise StorageError(f"Suppression refusée par le stockage objet ({r.status_code}).")

    def ping(self) -> bool:
        try:
            return self._request("HEAD", "").status_code == 200
        except StorageError:
            return False
