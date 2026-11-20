"""Horodatage de confiance RFC 3161 : demande à une autorité d'horodatage (TSA) et vérification de la réponse.

[RFC 3161 ; ISO/IEC 27037 ; plan : horodatage des pièces et des points de contrôle d'audit] Seule l'empreinte d'un message
« keryx-v1:<type>:<id>:<sha256> » quitte Keryx, jamais le contenu. La réponse est vérifiée (signature, chaîne jusqu'aux
certificats d'autorité configurés, empreinte et nonce de la demande) avant d'être conservée ; elle peut être revérifiée
à tout moment, hors ligne, avec les mêmes certificats.
"""
from __future__ import annotations

import datetime as dt

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


def _verifier(request, roots, intermediates):
    b = VerifierBuilder.from_request(request) if request is not None else VerifierBuilder()
    for r in roots:
        b = b.add_root_certificate(r)
    for i in intermediates:
        b = b.add_intermediate_certificate(i)
    return b.build()


def stamp(tsa_url: str, message: bytes, ca_file: str | None, http: httpx.Client | None = None) -> dict:
    roots, inter = load_authorities(ca_file)
    request = (TimestampRequestBuilder().data(message).hash_algorithm(HashAlgorithm.SHA256)
               .nonce(nonce=True).cert_request(cert_request=True).build())
    client = http or httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False)
    try:
        r = client.post(tsa_url, content=request.as_bytes(), headers={"Content-Type": "application/timestamp-query"})
    except httpx.HTTPError as exc:
        raise TimestampError("L'autorité d'horodatage est injoignable.") from exc
    if r.status_code != 200:
        raise TimestampError(f"L'autorité d'horodatage a répondu {r.status_code}.")
    try:
        response = decode_timestamp_response(r.content)
    except ValueError as exc:
        raise TimestampError("Réponse de l'autorité d'horodatage illisible.") from exc
    if response.status not in (PKIStatus.GRANTED, PKIStatus.GRANTED_WITH_MODS):
        raise TimestampError("L'autorité d'horodatage a refusé la demande.")
    try:
        _verifier(request, roots, inter).verify_message(response, message)
    except (VerificationError, ValueError) as exc:
        raise TimestampError(f"Réponse de l'autorité d'horodatage non valide : {exc}") from exc
    info = response.tst_info
    gen = info.gen_time if info.gen_time.tzinfo else info.gen_time.replace(tzinfo=dt.timezone.utc)
    return {"token": response.as_bytes(), "gen_time": gen, "serial": str(info.serial_number)}


def verify(token: bytes, message: bytes, ca_file: str | None) -> dt.datetime:
    """Revérifie un jeton conservé (signature et chaîne) et renvoie l'heure attestée. Lève TimestampError sinon."""
    roots, inter = load_authorities(ca_file)
    try:
        response = decode_timestamp_response(token)
        _verifier(None, roots, inter).verify_message(response, message)
    except (VerificationError, ValueError) as exc:
        raise TimestampError(f"Jeton d'horodatage non valide : {exc}") from exc
    t = response.tst_info.gen_time
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
