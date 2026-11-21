"""Clés de sécurité WebAuthn / FIDO2 : second facteur en option, à la place du code TOTP.

[RFC 8809 / W3C WebAuthn niveau 2 ; ASVS 5.0 chap. 6 (authentification multifacteur résistante à l'hameçonnage)]
Le mot de passe reste obligatoire (premier facteur) ; une clé enregistrée peut remplacer le TOTP à l'étape 2.
Le TOTP et les codes de secours restent disponibles : la perte d'une clé ne bloque pas le compte.
L'origine attendue est celle de KERYX_PUBLIC_URL, l'identifiant de partie de confiance son nom d'hôte.
"""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

import json

from . import audit, security
from .ids import rfc3339, utcnow
from .models import Session, User, WebAuthnCredential


class RegisterFinishIn(BaseModel):
    credential: dict
    name: str = Field(min_length=1, max_length=80)


class RegisterBeginIn(BaseModel):
    password: str = Field(max_length=256)


class AuthFinishIn(BaseModel):
    credential: dict


def register(app, ctx) -> None:
    get_db, current_user, commit, settings = ctx.get_db, ctx.current_user, ctx.commit, ctx.settings
    host = urlparse(settings.public_url).hostname or "localhost"
    origin = settings.public_url.rstrip("/")

    def creds(db: DbSession, user: User) -> list[WebAuthnCredential]:
        return db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
                          .order_by(WebAuthnCredential.created_at)).all()

    # ---------------------------------------------------------------- enregistrement (session complète)
    @app.get("/api/v1/me/webauthn")
    def list_keys(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        return {"items": [{"id": c.id, "name": c.name, "created_at": rfc3339(c.created_at),
                           "last_used_at": rfc3339(c.last_used_at)} for c in creds(db, user)]}

    @app.post("/api/v1/me/webauthn/register/begin")
    def register_begin(body: RegisterBeginIn, request: Request, user: User = Depends(current_user),
                       db: DbSession = Depends(get_db)):
        if not security.verify_password(user.password_hash, body.password):
            raise HTTPException(403, "Mot de passe incorrect.")
        options = generate_registration_options(
            rp_id=host, rp_name="Keryx", user_id=user.id.encode(), user_name=user.username,
            user_display_name=user.display_name,
            exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in creds(db, user)],
            authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.DISCOURAGED,
                                                                   user_verification=UserVerificationRequirement.PREFERRED))
        s = ctx.session_from_cookie(request, db)
        s.webauthn_challenge = bytes_to_base64url(options.challenge)
        db.commit()
        return json.loads(options_to_json(options))

    @app.post("/api/v1/me/webauthn/register/finish", status_code=201)
    def register_finish(body: RegisterFinishIn, request: Request, user: User = Depends(current_user),
                        db: DbSession = Depends(get_db)):
        s = ctx.session_from_cookie(request, db)
        if not s or not s.webauthn_challenge:
            raise HTTPException(409, "Aucun enregistrement en cours.")
        challenge, s.webauthn_challenge = base64url_to_bytes(s.webauthn_challenge), None
        try:
            v = verify_registration_response(credential=body.credential, expected_challenge=challenge,
                                             expected_rp_id=host, expected_origin=origin)
        except Exception as exc:  # noqa: BLE001 - la bibliothèque lève des erreurs variées : tout est un refus
            db.commit()
            raise HTTPException(422, "Clé refusée : vérification impossible.") from exc
        cid = bytes_to_base64url(v.credential_id)
        if db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cid)).first():
            raise HTTPException(409, "Cette clé est déjà enregistrée.")
        db.add(WebAuthnCredential(user_id=user.id, credential_id=cid, public_key=bytes_to_base64url(v.credential_public_key),
                                  sign_count=v.sign_count, name=body.name))
        audit.record(db, user.username, "auth.webauthn_registered", "user", user.id, None, {"name": body.name})
        commit(db)
        return {"status": "ok"}

    @app.delete("/api/v1/me/webauthn/{key_id}")
    def delete_key(key_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        c = db.get(WebAuthnCredential, key_id[:36])
        if c is None or c.user_id != user.id:
            raise HTTPException(404, "Clé introuvable.")
        db.delete(c)
        audit.record(db, user.username, "auth.webauthn_removed", "user", user.id, None, {"name": c.name})
        commit(db)
        return {"status": "ok"}

    # ---------------------------------------------------------------- connexion (étape 2, session « mot de passe »)
    def pending(request: Request, db: DbSession) -> tuple[Session, User]:
        s = ctx.session_from_cookie(request, db)
        if s is None or s.stage != "password":
            raise HTTPException(401, "Étape mot de passe requise.")
        user = db.get(User, s.user_id)
        if user is None or not user.active or not user.enrolled:
            raise HTTPException(401, "Étape mot de passe requise.")
        if ctx.sso_only(user):  # SSO obligatoire : pas de second facteur local pour un compte non Admin
            raise HTTPException(403, "La connexion par mot de passe est désactivée : utilisez l'authentification unique (SSO).")
        ip = ctx.client_ip(request)
        # La session de la requête est passée au limiteur : elle tient déjà le verrou SQLite (voir DbRateLimiter).
        if not ctx.login_ip_limiter.allow(ip, db) or not ctx.login_user_limiter.allow(user.username.lower(), db):
            raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
        return s, user

    @app.post("/api/v1/auth/webauthn/begin")
    def auth_begin(request: Request, db: DbSession = Depends(get_db)):
        s, user = pending(request, db)
        keys = creds(db, user)
        if not keys:
            raise HTTPException(409, "Aucune clé de sécurité enregistrée pour ce compte.")
        options = generate_authentication_options(
            rp_id=host, user_verification=UserVerificationRequirement.PREFERRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in keys])
        s.webauthn_challenge = bytes_to_base64url(options.challenge)
        db.commit()
        return json.loads(options_to_json(options))

    @app.post("/api/v1/auth/webauthn/finish")
    def auth_finish(body: AuthFinishIn, request: Request, response: Response, db: DbSession = Depends(get_db)):
        s, user = pending(request, db)
        ip = ctx.client_ip(request)
        if not s.webauthn_challenge:
            raise HTTPException(409, "Aucune authentification en cours.")
        challenge, s.webauthn_challenge = base64url_to_bytes(s.webauthn_challenge), None
        raw_id = body.credential.get("rawId") or body.credential.get("id") or ""
        cred = db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id,
                                                           WebAuthnCredential.credential_id == raw_id)).first()
        try:
            if cred is None:
                raise ValueError("clé inconnue")
            v = verify_authentication_response(
                credential=body.credential, expected_challenge=challenge, expected_rp_id=host, expected_origin=origin,
                credential_public_key=base64url_to_bytes(cred.public_key), credential_current_sign_count=cred.sign_count,
                require_user_verification=False)
        except Exception as exc:  # noqa: BLE001
            ctx.count_second_factor_failure(db, user, ip)
            raise HTTPException(401, "Clé de sécurité refusée.") from exc
        cred.sign_count, cred.last_used_at = v.new_sign_count, utcnow()
        return ctx.promote(db, s, user, response, ip, "webauthn")
