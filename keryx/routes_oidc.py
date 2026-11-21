"""Routes de l'authentification unique OIDC (Keycloak). Voir oidc.py pour les contrôles du jeton.

Le titulaire doit déjà avoir un compte Keryx (créé par l'Admin) : le SSO n'en crée jamais. La première connexion lie
l'identité fédérée (émetteur + « sub ») au compte, à condition que l'adresse courriel vérifiée du jeton soit celle du
compte Keryx (sinon n'importe quel utilisateur du realm portant le même identifiant pourrait prendre le compte).
La double authentification est celle du realm Keycloak (à imposer côté Keycloak, PDIS IV.3.9).
"""
from __future__ import annotations

import secrets
from datetime import timedelta
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from . import audit, security
from .ids import as_utc, utcnow
from .models import OidcFlow, User
from .oidc import Discovery, OidcError, pkce_pair

FLOW_MINUTES = 10


def register(app, ctx) -> None:
    get_db, settings, commit = ctx.get_db, ctx.settings, ctx.commit
    providers = ctx.oidc_providers
    discoveries = {name: Discovery(p) for name, p in providers.items()}

    def redirect_uri(name: str) -> str:
        return f"{settings.public_url.rstrip('/')}/api/v1/auth/oidc/{name}/callback"

    def fail(db: DbSession, reason: str, code: str, name: str, ip: str, username: str | None = None) -> RedirectResponse:
        audit.record(db, username or "anonyme", "auth.sso_failed", None, None, None, {"provider": name, "reason": reason, "ip": ip})
        commit(db)
        return RedirectResponse(f"/connexion?sso_error={quote(code)}", status_code=303)

    def sso_logout_url(name: str, id_token: str) -> str | None:
        if name not in providers:
            return None
        return discoveries[name].logout_url(id_token, f"{settings.public_url.rstrip('/')}/connexion")

    ctx.sso_logout_url = sso_logout_url

    @app.get("/api/v1/auth/providers")
    def list_providers():
        return {"items": [{"name": p.name, "label": p.label} for p in providers.values()],
                "local_login_enabled": not settings.oidc_enforce}

    @app.get("/api/v1/auth/oidc/{name}/start")
    def start(name: str, request: Request, db: DbSession = Depends(get_db)):
        if name not in providers:
            raise HTTPException(404, "Fournisseur d'identité inconnu.")
        ip = ctx.client_ip(request)
        if not ctx.login_ip_limiter.allow(ip):
            raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier, challenge = pkce_pair()
        now = utcnow()
        db.execute(delete(OidcFlow).where(OidcFlow.expires_at < now))  # ménage des flux expirés
        db.add(OidcFlow(state_hash=security.sha256(state), provider=name, nonce=nonce, code_verifier=verifier,
                        expires_at=now + timedelta(minutes=FLOW_MINUTES)))
        db.commit()
        try:
            url = discoveries[name].authorization_url(redirect_uri(name), state, nonce, challenge)
        except OidcError:
            return RedirectResponse("/connexion?sso_error=indisponible", status_code=303)
        return RedirectResponse(url, status_code=303)

    @app.get("/api/v1/auth/oidc/{name}/callback")
    def callback(name: str, request: Request, code: str | None = None, state: str | None = None,
                 error: str | None = None, db: DbSession = Depends(get_db)):
        if name not in providers:
            raise HTTPException(404, "Fournisseur d'identité inconnu.")
        ip = ctx.client_ip(request)
        if not ctx.login_ip_limiter.allow(ip):
            raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
        if error or not code or not state:
            return fail(db, error or "paramètres manquants", "refuse", name, ip)
        flow = db.get(OidcFlow, security.sha256(state))
        if flow is not None:
            db.delete(flow)  # usage unique : l'état ne sert qu'une fois, quel que soit le résultat
            db.commit()
        if flow is None or flow.provider != name or as_utc(flow.expires_at) < utcnow():
            return fail(db, "état inconnu ou expiré", "etat", name, ip)
        disc = discoveries[name]
        try:
            id_token = disc.exchange(code, redirect_uri(name), flow.code_verifier)
            claims = disc.verify(id_token, flow.nonce, settings.oidc_required_acr)
        except OidcError as exc:
            return fail(db, str(exc), "jeton", name, ip)
        issuer, sub = providers[name].issuer, claims["sub"]
        user = db.scalars(select(User).where(User.oidc_issuer == issuer, User.oidc_sub == sub)).first()
        if user is None:
            uname = str(claims.get("preferred_username") or "")[:120]
            cand = db.scalars(select(User).where(User.username == uname)).first() if uname else None
            email, verified = str(claims.get("email") or "").lower(), claims.get("email_verified") is True
            if cand is None or cand.oidc_sub is not None:
                return fail(db, "aucun compte Keryx lié à cette identité", "inconnu", name, ip, uname)
            if not (verified and cand.email and cand.email.lower() == email):
                return fail(db, "liaison refusée : courriel vérifié différent ou absent", "liaison", name, ip, uname)
            cand.oidc_issuer, cand.oidc_sub = issuer, sub
            user = cand
            audit.record(db, user.username, "auth.sso_linked", "user", user.id, None, {"provider": name})
        if not user.active:
            return fail(db, "compte inactif", "inconnu", name, ip, user.username)
        if user.locked_until and as_utc(user.locked_until) > utcnow():
            return fail(db, "compte verrouillé", "verrouille", name, ip, user.username)
        # Une connexion SSO réussie remplace toute session en cours de ce navigateur
        old = request.cookies.get(ctx.SESSION_COOKIE)
        resp = RedirectResponse("/", status_code=303)
        if old:
            from .models import Session
            s = db.get(Session, security.sha256(old))
            if s is not None:
                db.delete(s)
        ctx.open_session(db, user, resp, ip, "sso", sso=(name, id_token))
        return resp

    @app.post("/api/v1/admin/users/{username}/unlink-sso", dependencies=[Depends(ctx.admin_guard)])
    def unlink(username: str, user: User = Depends(ctx.current_user), db: DbSession = Depends(get_db)):
        ctx.require_role(user, "admin")
        u = db.scalars(select(User).where(User.username == username[:120])).first()
        if u is None:
            raise HTTPException(404, "Utilisateur introuvable.")
        u.oidc_issuer = u.oidc_sub = None
        audit.record(db, user.username, "user.sso_unlinked", "user", u.id)
        commit(db)
        return {"status": "ok"}
