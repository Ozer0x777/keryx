"""Horodatage de confiance RFC 3161 : demande à une autorité d'horodatage (TSA) et vérification de la réponse.

[RFC 3161 ; ISO/IEC 27037 ; plan : horodatage des pièces et des points de contrôle d'audit] Seule l'empreinte d'un message
« keryx-v1:<type>:<id>:<sha256> » quitte Keryx, jamais le contenu. La réponse est vérifiée (signature, chaîne jusqu'aux
certificats d'autorité configurés, empreinte et nonce de la demande) avant d'être conservée ; elle peut être revérifiée
à tout moment, hors ligne, avec les mêmes certificats.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import subprocess
import tempfile

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from rfc3161_client import (HashAlgorithm, PKIStatus, TimestampRequestBuilder, VerifierBuilder, decode_timestamp_response)
from rfc3161_client.errors import VerificationError

HTTP_TIMEOUT = 10.0


class TimestampError(Exception):
    """Erreur d'horodatage : le message est destiné à l'utilisateur."""


def message_for(object_type: str, object_id: str, digest: str) -> bytes:
    return f"keryx-v1:{object_type}:{object_id}:{digest}".encode()


def load_authorities(pem_path: str | None) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Renvoie (racines, intermédiaires) lus dans un fichier PEM : un certificat auto-signé est une racine."""
    if not pem_path:
        raise TimestampError("Certificats de l'autorité d'horodatage non configurés (KERYX_TSA_CA_FILE).")
    try:
        with open(pem_path, "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())
    except (OSError, ValueError) as exc:
        raise TimestampError("Certificats de l'autorité d'horodatage illisibles.") from exc
    roots = [c for c in certs if c.issuer == c.subject]
    if not roots:
        raise TimestampError("Aucun certificat racine dans le fichier de l'autorité d'horodatage.")
    return roots, [c for c in certs if c.issuer != c.subject]


def _verifier(request, roots, intermediates, policy_oid: str | None = None):
    b = VerifierBuilder.from_request(request) if request is not None else VerifierBuilder()
    if policy_oid:
        b = b.policy_id(x509.ObjectIdentifier(policy_oid))   # la réponse doit porter la politique attendue
    for r in roots:
        b = b.add_root_certificate(r)
    for i in intermediates:
        b = b.add_intermediate_certificate(i)
    return b.build()


# ---------------------------------------------------------------- vérification de secours par OpenSSL
# Certaines autorités (dont Certum, autorité de l'UE essayée) produisent des réponses dont l'ensemble de certificats n'est
# pas dans l'ordre DER canonique : le décodeur strict de rfc3161-client les refuse, OpenSSL les valide. Dans ce cas, la
# vérification passe par `openssl ts -verify` (l'outil doit être installé), à la date attestée (-attime).
_TIME = re.compile(r"Time stamp:\s+(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+(\d{4})")


def _openssl(*args: str) -> subprocess.CompletedProcess:
    exe = shutil.which("openssl")
    if not exe:
        raise TimestampError("Réponse non décodable par le décodeur strict et OpenSSL introuvable (installer le paquet openssl).")
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=30)


def _openssl_verify(token: bytes, message: bytes | None, request: bytes | None, ca_file: str, policy_oid: str | None) -> dict:
    with tempfile.TemporaryDirectory() as d:
        tok = os.path.join(d, "r.tsr")
        open(tok, "wb").write(token)
        text = _openssl("ts", "-reply", "-in", tok, "-text")
        m = _TIME.search(text.stdout)
        if text.returncode != 0 or not m:
            raise TimestampError("Réponse de l'autorité d'horodatage illisible.")
        when = dt.datetime.strptime(" ".join(m.groups()), "%b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc)
        serial = (re.search(r"Serial number:\s+(\S+)", text.stdout) or [None, "?"])[1]
        policy_found = (re.search(r"Policy OID:\s+(\S+)", text.stdout) or [None, ""])[1]
        args = ["ts", "-verify", "-in", tok, "-CAfile", ca_file, "-attime", str(int(when.timestamp()))]
        if request is not None:
            q = os.path.join(d, "q.tsq")
            open(q, "wb").write(request)
            args += ["-queryfile", q]
        else:
            msg = os.path.join(d, "m.bin")
            open(msg, "wb").write(message or b"")
            args += ["-data", msg]
        if policy_oid:
            # « openssl ts -verify » ne contrôle pas la politique : on la compare nous-mêmes (OID numérique obligatoire,
            # sinon on refuse plutôt que de supposer).
            found = (re.search(r"Policy OID:\s+(\S+)", text.stdout) or [None, ""])[1]
            if not re.fullmatch(r"\d+(\.\d+)+", found):
                raise TimestampError("Politique d'horodatage non vérifiable (identifiant non numérique dans la réponse).")
            if found != policy_oid:
                raise TimestampError(f"Politique d'horodatage inattendue : {found} (attendu : {policy_oid}).")
        v = _openssl(*args)
        if "Verification: OK" not in v.stdout + v.stderr:
            raise TimestampError("Réponse de l'autorité d'horodatage non valide : " + (v.stderr.strip().splitlines() or ["vérification refusée"])[-1][:160])
    return {"gen_time": when, "serial": serial, "policy": policy_found}


def make_client(settings) -> httpx.Client:
    """Client HTTP vers l'autorité, avec l'authentification configurée (Basic, Bearer ou certificat client)."""
    kwargs: dict = {"timeout": HTTP_TIMEOUT, "follow_redirects": False}
    if settings.tsa_user and settings.tsa_password:
        kwargs["auth"] = httpx.BasicAuth(settings.tsa_user, settings.tsa_password)
    elif settings.tsa_bearer:
        kwargs["headers"] = {"Authorization": f"Bearer {settings.tsa_bearer}"}
    if settings.tsa_client_cert:
        kwargs["cert"] = (settings.tsa_client_cert, settings.tsa_client_key) if settings.tsa_client_key else settings.tsa_client_cert
    return httpx.Client(**kwargs)


def stamp(tsa_url: str, message: bytes, ca_file: str | None, http: httpx.Client | None = None,
          policy_oid: str | None = None) -> dict:
    roots, inter = load_authorities(ca_file)
    request = (TimestampRequestBuilder().data(message).hash_algorithm(HashAlgorithm.SHA256)
               .nonce(nonce=True).cert_request(cert_request=True).build())
    client = http or httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False)
    try:
        r = client.post(tsa_url, content=request.as_bytes(), headers={"Content-Type": "application/timestamp-query"})
    except httpx.HTTPError as exc:
        raise TimestampError("L'autorité d'horodatage est injoignable.") from exc
    if r.status_code in (401, 403):
        raise TimestampError("L'autorité d'horodatage refuse l'authentification (vérifier KERYX_TSA_USER / _PASSWORD / _BEARER / certificat client).")
    if r.status_code != 200:
        raise TimestampError(f"L'autorité d'horodatage a répondu {r.status_code}.")
    try:
        response = decode_timestamp_response(r.content)
    except ValueError:
        # Décodage strict refusé (encodage DER non canonique) : vérification de secours par OpenSSL, au besoin
        v = _openssl_verify(r.content, None, request.as_bytes(), ca_file, policy_oid)
        return {"token": r.content, "gen_time": v["gen_time"], "serial": v["serial"], "policy": v["policy"]}
    if response.status not in (PKIStatus.GRANTED, PKIStatus.GRANTED_WITH_MODS):
        raise TimestampError("L'autorité d'horodatage a refusé la demande.")
    try:
        _verifier(request, roots, inter, policy_oid).verify_message(response, message)
    except (VerificationError, ValueError) as exc:
        raise TimestampError(f"Réponse de l'autorité d'horodatage non valide : {exc}") from exc
    info = response.tst_info
    gen = info.gen_time if info.gen_time.tzinfo else info.gen_time.replace(tzinfo=dt.timezone.utc)
    return {"token": response.as_bytes(), "gen_time": gen, "serial": str(info.serial_number), "policy": str(info.policy)}


def verify(token: bytes, message: bytes, ca_file: str | None, policy_oid: str | None = None) -> dt.datetime:
    """Revérifie un jeton conservé (signature et chaîne) et renvoie l'heure attestée. Lève TimestampError sinon."""
    roots, inter = load_authorities(ca_file)
    try:
        response = decode_timestamp_response(token)
    except ValueError:
        return _openssl_verify(token, message, None, ca_file, policy_oid)["gen_time"]
    try:
        _verifier(None, roots, inter, policy_oid).verify_message(response, message)
    except (VerificationError, ValueError) as exc:
        raise TimestampError(f"Jeton d'horodatage non valide : {exc}") from exc
    t = response.tst_info.gen_time
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
