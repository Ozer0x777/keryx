"""API REST de Keryx (FastAPI) et service de l'interface web.

Erreurs au format Problem Details [RFC 9457]. Sessions par cookie HttpOnly/Secure/SameSite
+ jeton CSRF en double soumission [RFC 6265, ASVS V3/V7]. En-têtes de sécurité
[RFC 6797 HSTS, RFC 9111 Cache-Control: no-store, CSP]. Limitation de débit [RFC 6585 : 429].
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, delete, false, func, or_, select, update
from sqlalchemy.orm import Session as DbSession
from starlette.background import BackgroundTask

from . import attachments as att
from . import audit, inbox, routes_admin, routes_oidc, routes_ops, routes_isi, routes_reports, routes_timestamp, routes_virustotal, routes_wazuh, routes_webauthn, routes_work, security
from . import wazuh_context
from .oidc import load_providers
from .bodylimit import BodyLimitMiddleware
from .config import Settings
from .db import Base, make_engine, make_session_factory
from .ids import as_utc, bounded_input_date, rfc3339, utcnow
from .iodef import validate as iodef_validate
from .ingest import AlertRejected, ingest_alert
from .mitre import valid_technique
from .models import (
    LIFECYCLE, SEVERITIES, STATUSES, TLP, VERDICTS, ApiKey, Attachment, AuditEntry, Comment, CustodyEvent, MitreTechnique, RateHit,
    RawAlert, Session, WebAuthnCredential, Tenant, Ticket, TicketEvent, User,
)
from .notify import retry_failed, send_pending
from .s3store import StorageError
from .sanitize import clean_html
from .sla import state as sla_state
from .severity import DOMMAGES, IMPORTANCES, gravite, is_rex_required
from .models import TERMINAL_STATUSES as TERMINAL
from .workflow import TransitionError, check_transition, rex_pending

SESSION_COOKIE = "keryx_session"
CSRF_COOKIE = "keryx_csrf"
PROBLEM = "application/problem+json"
IDLE_MINUTES = 30
GENERIC_LOGIN_ERROR = "Identifiant ou mot de passe incorrect, ou compte temporairement verrouillé."
SSO_ONLY_ERROR = "La connexion par mot de passe est désactivée : utilisez l'authentification unique (SSO)."
log = logging.getLogger("keryx")


# ---------------------------------------------------------------- erreurs RFC 9457
def problem(status: int, title: str, detail: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type=PROBLEM, headers={"Cache-Control": "no-store"})


MAX_VERSION_CHARS = 20_000
# Adresse d'une pièce citée dans un contenu riche (image insérée depuis l'éditeur).
EMBEDDED_ATTACHMENT = re.compile(r"/api/v1/attachments/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/content")


class RateLimiter:
    """Fenêtre glissante en mémoire, par clé. Suffisant pour un processus ; à mutualiser
    (Redis ou base) si plusieurs workers sont lancés."""

    def __init__(self, limit: int, window_s: int):
        self.limit, self.window = limit, window_s
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, db: DbSession | None = None) -> bool:  # db : ignoré (même signature que DbRateLimiter)
        now = time.monotonic()
        if len(self.hits) > 5000:  # purge des clés expirées (identifiants choisis par l'appelant)
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > self.window]:
                del self.hits[k]
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


class DbRateLimiter:
    """Même contrat que RateLimiter, mais le compte vit en base : plusieurs processus partagent la même limite.
    Approximatif sous forte concurrence (deux requêtes simultanées peuvent dépasser la limite d'une unité).

    Les routes passent la session de la requête (`db`) : le compte est écrit et validé dans cette session. Sur SQLite,
    elle tient déjà le verrou d'écriture dès sa première lecture (BEGIN IMMEDIATE) ; une seconde session attendrait ce
    verrou 15 s puis échouerait (erreur 500). Sans `db`, le limiteur ouvre sa propre session : à n'utiliser que si
    l'appelant n'a aucune transaction en cours."""

    def __init__(self, session_factory, name: str, limit: int, window_s: int):
        self.sf, self.name, self.limit, self.window = session_factory, name, limit, window_s
        self.calls = 0

    def allow(self, key: str, db: DbSession | None = None) -> bool:
        k = f"{self.name}:{key}"[:200]
        now = utcnow()
        own = db is None
        if own:
            db = self.sf()
        try:
            db.execute(delete(RateHit).where(RateHit.key == k, RateHit.ts < now - timedelta(seconds=self.window)))
            n = db.scalar(select(func.count()).select_from(RateHit).where(RateHit.key == k)) or 0
            ok = n < self.limit
            if ok:
                db.add(RateHit(key=k, ts=now))
            self.calls += 1
            if self.calls % 500 == 0:  # ménage global : plus rien de plus vieux qu'une heure
                db.execute(delete(RateHit).where(RateHit.ts < now - timedelta(hours=1)))
            db.commit()  # validé tout de suite : le passage compte même si la requête échoue ensuite
            return ok
        finally:
            if own:
                db.close()


def _reject_constant(name: str):
    raise ValueError(f"constante JSON interdite : {name}")


def _no_control_chars(v: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ValueError("caractères de contrôle interdits")
    return v


# ---------------------------------------------------------------- schémas
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(max_length=256)
    _u = field_validator("username")(_no_control_chars)


class EnrollStartIn(BaseModel):
    activation_code: str = Field(min_length=8, max_length=64)


class EnrollIn(BaseModel):
    code: str = Field(max_length=12)
    new_password: str = Field(min_length=12, max_length=256)


class TotpIn(BaseModel):
    code: str | None = Field(default=None, max_length=12)
    recovery_code: str | None = Field(default=None, max_length=32)


class QualificationIn(BaseModel):
    verdict: str | None = None
    dommages: str | None = None
    importance: str | None = None
    impact: str | None = Field(default=None, max_length=5000)
    risque: str | None = Field(default=None, max_length=5000)
    tlp: str | None = None


class StatusIn(BaseModel):
    status: str


class CommentIn(BaseModel):
    body_html: str = Field(max_length=100_000)
    visible_client: bool = False


class BodyIn(BaseModel):
    body_html: str = Field(max_length=200_000)


class MitreIn(BaseModel):
    techniques: list[str] = Field(max_length=50)


class AssignIn(BaseModel):
    username: str | None = Field(default=None, max_length=120)


class SyntheseIn(BaseModel):
    compromission_initiale: datetime | None = None
    chronologie: str | None = Field(default=None, max_length=100_000)
    mode_operatoire: str | None = Field(default=None, max_length=100_000)
    perimetre: str | None = Field(default=None, max_length=100_000)
    rex_html: str | None = Field(default=None, max_length=100_000)


class ExternalEvidenceIn(BaseModel):
    description: str = Field(min_length=3, max_length=5000)
    collected_at: datetime
    method: str = Field(min_length=3, max_length=500)
    sensitivity: str = "TLP:AMBER"
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    location: str = Field(min_length=3, max_length=500)
    size: int = Field(default=0, ge=0, le=2**50)
    filename: str = Field(default="preuve externe", max_length=200)


class LifecycleIn(BaseModel):
    lifecycle: str
    reason: str = Field(min_length=3, max_length=500)


# Cycle de vie d'une pièce : états atteignables depuis chaque état [PRIS VI.2.4].
LIFECYCLE_NEXT = {"conserve": ("restitue", "detruit"), "restitue": ("detruit",)}


# ---------------------------------------------------------------- application
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    box = security.SecretBox(settings.secret_key)
    audit.configure(settings.secret_key)
    engine = make_engine(settings.database_url)
    if settings.auto_create_schema:
        Base.metadata.create_all(engine)  # tests uniquement ; sinon `alembic upgrade head`
    SessionLocal = make_session_factory(engine)
    oidc_providers = load_providers(settings.oidc_providers, settings.oidc_allow_http)
    shared = (settings.rate_limit_backend or ("db" if settings.database_url.startswith("postgresql") else "memory")) == "db"

    def limiter(name: str, limit: int, window_s: int):
        return DbRateLimiter(SessionLocal, name, limit, window_s) if shared else RateLimiter(limit, window_s)

    login_ip_limiter = limiter("login_ip", settings.login_ip_limit, 300)
    login_user_limiter = limiter("login_user", settings.login_user_limit, 300)
    ingest_fail_limiter = limiter("ingest_fail", 20, 60)
    ingest_limiter = limiter("ingest", 600, 60)

    # Pas d'interface Swagger : elle charge ses scripts depuis un CDN (aucun service externe).
    app = FastAPI(title="Keryx", version="0.7.0", docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.engine = engine
    app.state.SessionLocal = SessionLocal
    app.state.box = box

    # -- erreurs
    @app.exception_handler(HTTPException)
    async def _http_exc(_req: Request, exc: HTTPException):
        return problem(exc.status_code, _title(exc.status_code), str(exc.detail) if exc.detail else None)

    @app.exception_handler(RequestValidationError)
    async def _val_exc(_req: Request, exc: RequestValidationError):
        return problem(422, "Requête invalide", "; ".join(str(e.get("msg", "")) for e in exc.errors())[:500])

    @app.exception_handler(Exception)
    async def _any_exc(_req: Request, exc: Exception):
        log.exception("Erreur interne")
        return problem(500, "Erreur interne", "Une erreur inattendue est survenue.")

    # -- en-têtes de sécurité
    @app.middleware("http")
    async def _headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        # setdefault : une route peut imposer une politique plus stricte (pièces servies en ligne).
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # -- taille des corps de requête, bornée avant toute lecture (voir bodylimit.py)
    def _has_full_session(token: str) -> bool:
        db = SessionLocal()
        try:
            s = db.get(Session, security.sha256(token))
            return bool(s and s.stage == "full" and as_utc(s.expires_at) > utcnow())
        finally:
            db.close()

    app.add_middleware(BodyLimitMiddleware, default_limit=settings.max_body_bytes, cookie_name=SESSION_COOKIE,
                       has_session=_has_full_session, large=[
                           (re.compile(r"^/api/v1/tickets/[^/]+/attachments$"), settings.max_attachment_bytes + 1024 * 1024),
                           (re.compile(r"^/api/v1/mitre/import$"), routes_ops.MAX_STIX_BYTES + 1024 * 1024)])

    # -- dépendances
    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def commit(db: DbSession) -> None:
        new_entries = db.info.pop("audit_new", [])
        db.commit()
        if settings.syslog_host:
            for e in new_entries:  # pragma: no cover - réseau
                try:
                    audit.send_syslog(audit.to_syslog(e, settings.hostname), settings.syslog_host, settings.syslog_port)
                except OSError:
                    pass

    def _session_from_cookie(request: Request, db: DbSession) -> Session | None:
        token = request.cookies.get(SESSION_COOKIE)
        if not token or len(token) > 100:
            return None
        s = db.get(Session, security.sha256(token))
        now = utcnow()
        if s is None or as_utc(s.expires_at) < now:
            return None
        if s.stage == "full" and as_utc(s.last_seen_at) < now - timedelta(minutes=IDLE_MINUTES):
            return None  # inactivité prolongée [ASVS V7]
        if s.stage == "full" and as_utc(s.last_seen_at) < now - timedelta(seconds=60):
            s.last_seen_at = now
            db.commit()
        return s

    def current_user(request: Request, db: DbSession = Depends(get_db),
                     x_csrf_token: str | None = Header(default=None)) -> User:
        s = _session_from_cookie(request, db)
        if s is None or s.stage != "full":
            raise HTTPException(401, "Authentification requise (mot de passe + code TOTP).")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not x_csrf_token or not security.hmac_equal(x_csrf_token, s.csrf_token):
                raise HTTPException(403, "Jeton CSRF manquant ou invalide.")
        user = db.get(User, s.user_id)
        if user is None or not user.active:
            raise HTTPException(401, "Compte inactif.")
        if user.locked_until and as_utc(user.locked_until) > utcnow():
            raise HTTPException(401, "Compte verrouillé.")
        return user

    def visible_tenant_ids(user: User) -> list[str]:
        """Cloisonnement par client [PDIS IV.3.8.g]. L'admin ne voit aucun ticket [PDIS IV.3.9]."""
        if user.role == "admin":
            return []
        return [t.id for t in user.tenants]

    def load_ticket(db: DbSession, user: User, ref: str) -> Ticket:
        if user.role == "admin":
            audit.record(db, user.username, "ticket.access_denied", "ticket", ref[:32], None, {"role": "admin"})
            commit(db)
            raise HTTPException(403, "Le rôle Admin n'a pas accès au contenu des tickets.")
        t = db.scalars(select(Ticket).where(Ticket.ref == ref[:32])).first()
        # 404 aussi pour un ticket d'un autre client : on ne révèle pas son existence.
        if t is None or t.tenant_id not in visible_tenant_ids(user):
            audit.record(db, user.username, "ticket.access_denied", "ticket", ref[:32], None, {})
            commit(db)
            raise HTTPException(404, "Ticket introuvable.")
        return t

    def load_attachment(db: DbSession, user: User, attachment_id: str) -> tuple[Attachment, Ticket]:
        a = db.get(Attachment, attachment_id[:36])
        if a is None or a.tenant_id not in visible_tenant_ids(user):
            raise HTTPException(404, "Pièce introuvable.")
        if user.role == "client" and not a.visible_client:
            raise HTTPException(404, "Pièce introuvable.")
        return a, db.get(Ticket, a.ticket_id)

    def require_role(user: User, *roles: str) -> None:
        if user.role not in roles:
            raise HTTPException(403, "Action non autorisée pour ce rôle.")

    def admin_guard(user: User = Depends(current_user)) -> None:
        """Contrôle de rôle placé AVANT la validation du corps : un non-admin reçoit 403, jamais le détail du schéma."""
        require_role(user, "admin")

    def input_date(value: datetime | None, what: str, future_days: int = 1) -> datetime | None:
        try:
            return bounded_input_date(value, what, future_days)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    def require_open(t: Ticket) -> None:
        if t.status in TERMINAL:
            raise HTTPException(409, "Ticket clos : modification impossible.")

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "inconnu"

    def event(db, t: Ticket, user: User, action: str, details: dict, visible_client: bool = False):
        db.add(TicketEvent(ticket_id=t.id, actor=user.username, action=action, details=details,
                           visible_client=visible_client))
        audit.record(db, user.username, f"ticket.{action}", "ticket", t.ref, t.tenant_id, details)

    def _lock(user: User) -> None:
        user.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
        user.failed_attempts = 0

    def sso_only(user: User) -> bool:
        """SSO obligatoire (KERYX_OIDC_ENFORCE) : seul l'Admin garde une authentification locale [ADR-0017]."""
        return bool(settings.oidc_enforce and oidc_providers and user.role != "admin")

    # ---------------------------------------------------------------- santé
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    # ---------------------------------------------------------------- authentification
    @app.post("/api/v1/auth/login")
    def login(body: LoginIn, request: Request, response: Response, db: DbSession = Depends(get_db)):
        ip = client_ip(request)
        if not login_ip_limiter.allow(ip, db) or not login_user_limiter.allow(body.username.lower(), db):
            raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
        now = utcnow()
        db.execute(delete(Session).where(Session.expires_at < now))  # ménage des sessions expirées
        user = db.scalars(select(User).where(User.username == body.username)).first()
        locked = bool(user and user.locked_until and as_utc(user.locked_until) > now)
        # Toujours une vérification Argon2 (même durée que l'identifiant existe ou non).
        ok = security.verify_password(user.password_hash if user else None, body.password)
        if not user or not user.active or locked or not ok:
            # Pas de verrouillage sur le mot de passe (sinon n'importe qui bloquerait un compte) :
            # la limitation par identifiant et par IP freine la force brute.
            audit.record(db, body.username, "auth.login_failed", "user", user.id if user else None, None,
                         {"ip": ip, "locked": locked})
            commit(db)
            raise HTTPException(401, GENERIC_LOGIN_ERROR)
        if sso_only(user):
            # SSO obligatoire (seul l'Admin garde le mot de passe local, accès de secours) : annoncé après la vérification
            # du mot de passe pour ne pas révéler l'existence des comptes. Aucune session intermédiaire n'est ouverte,
            # que le compte soit enrôlé ou non : l'enrôlement local donnerait sinon une session complète sans SSO.
            audit.record(db, user.username, "auth.local_login_refused", "user", user.id, None, {"ip": ip})
            commit(db)
            raise HTTPException(403, SSO_ONLY_ERROR)
        token = security.new_token()
        db.add(Session(token_hash=security.sha256(token), user_id=user.id, stage="password",
                       csrf_token=security.new_token(), expires_at=now + timedelta(minutes=5)))
        audit.record(db, user.username, "auth.password_ok", "user", user.id, None, {"ip": ip})
        commit(db)
        _set_cookie(response, SESSION_COOKIE, token, settings, http_only=True, max_age=300)
        has_key = bool(db.scalars(select(WebAuthnCredential.id).where(WebAuthnCredential.user_id == user.id).limit(1)).first())
        return {"next": "totp" if user.enrolled else "enroll", "webauthn": has_key and user.enrolled}

    def count_second_factor_failure(db: DbSession, user: User, ip: str) -> None:
        """Échec du second facteur (TOTP, code de secours ou clé de sécurité) : compte, verrouille, journalise."""
        failures = db.execute(update(User).where(User.id == user.id)
                              .values(failed_attempts=User.failed_attempts + 1)
                              .returning(User.failed_attempts)).scalar_one()
        db.refresh(user)
        if failures >= settings.max_failed_logins:
            _lock(user)
            db.execute(delete(Session).where(Session.user_id == user.id, Session.stage == "password"))
        audit.record(db, user.username, "auth.totp_failed", "user", user.id, None, {"ip": ip})
        commit(db)

    def promote(db: DbSession, s: Session, user: User, response: Response, ip: str, method: str) -> dict:
        """Élève une session « mot de passe » en session complète (rotation du jeton : anti-fixation)."""
        db.delete(s)
        return open_session(db, user, response, ip, method)

    def open_session(db: DbSession, user: User, response: Response, ip: str, method: str,
                     sso: tuple[str, str] | None = None) -> dict:
        """Ouvre une session complète neuve (jeton neuf, CSRF neuf) et pose les cookies.
        `sso` = (fournisseur, jeton d'identité) : conservé chiffré pour la déconnexion unique."""
        token, csrf = security.new_token(), security.new_token()
        th = security.sha256(token)
        db.add(Session(token_hash=th, user_id=user.id, stage="full", csrf_token=csrf,
                       sso_provider=sso[0] if sso else None,
                       sso_id_token=box.encrypt(sso[1], f"sso:{th}") if sso else None,
                       expires_at=utcnow() + timedelta(hours=settings.session_hours)))
        user.failed_attempts = 0
        user.last_login_at = utcnow()
        audit.record(db, user.username, "auth.login_success", "user", user.id, None, {"ip": ip, "method": method})
        commit(db)
        max_age = settings.session_hours * 3600
        _set_cookie(response, SESSION_COOKIE, token, settings, http_only=True, max_age=max_age)
        _set_cookie(response, CSRF_COOKIE, csrf, settings, http_only=False, max_age=max_age)
        return {"csrf_token": csrf, "role": user.role, "display_name": user.display_name,
                "recovery_codes_left": len(user.recovery_codes or [])}

    def enrolling_user(request: Request, db: DbSession) -> tuple[Session, User, str]:
        ip = client_ip(request)
        s = _session_from_cookie(request, db)
        if s is None or s.stage != "password":
            raise HTTPException(401, "Étape mot de passe requise.")
        user = db.get(User, s.user_id)
        if user is None or not user.active or user.enrolled:
            raise HTTPException(409, "Aucun enrôlement en attente pour ce compte.")
        if sso_only(user):
            # SSO obligatoire : pas d'enrôlement local pour un compte non Admin (il ouvrirait une session complète).
            db.delete(s)
            audit.record(db, user.username, "auth.local_login_refused", "user", user.id, None, {"ip": ip, "etape": "enrolement"})
            commit(db)
            raise HTTPException(403, SSO_ONLY_ERROR)
        if not login_ip_limiter.allow(ip, db) or not login_user_limiter.allow(user.username.lower(), db):
            raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
        return s, user, ip

    @app.post("/api/v1/auth/enroll/start")
    def enroll_start(body: EnrollStartIn, request: Request, db: DbSession = Depends(get_db)):
        """Première connexion : le secret TOTP est généré ici et montré à son seul titulaire, qui prouve son
        identité par le code d'activation reçu hors de l'Admin (le mot de passe temporaire ne suffit pas)."""
        s, user, ip = enrolling_user(request, db)
        ok = (user.enroll_code_hash and user.enroll_code_expires and as_utc(user.enroll_code_expires) > utcnow()
              and hmac.compare_digest(user.enroll_code_hash, security.sha256(body.activation_code.strip())))
        if not ok:
            audit.record(db, user.username, "auth.enroll_code_invalid", "user", user.id, None, {"ip": ip})
            commit(db)
            raise HTTPException(401, "Code d'activation invalide ou expiré.")
        secret = security.new_totp_secret()
        user.totp_secret = box.encrypt(secret, f"totp:{user.id}")
        audit.record(db, user.username, "auth.enroll_start", "user", user.id)
        commit(db)
        return {"totp_uri": security.totp_uri(secret, user.username), "totp_secret": secret}

    @app.post("/api/v1/auth/enroll/finish")
    def enroll_finish(body: EnrollIn, request: Request, response: Response, db: DbSession = Depends(get_db)):
        s, user, ip = enrolling_user(request, db)
        if not user.totp_secret:
            raise HTTPException(409, "Démarrer l'enrôlement avant de le valider.")
        step = security.verify_totp(box.decrypt(user.totp_secret, f"totp:{user.id}"), body.code, None)
        if step is None:
            audit.record(db, user.username, "auth.enroll_failed", "user", user.id, None, {"ip": ip})
            commit(db)
            raise HTTPException(401, "Code de vérification invalide.")
        if security.verify_password(user.password_hash, body.new_password):
            raise HTTPException(422, "Choisissez un mot de passe différent du mot de passe temporaire.")
        user.password_hash = security.hash_password(body.new_password)
        plain, hashed = security.new_recovery_codes()
        user.recovery_codes, user.last_totp_step, user.enrolled = hashed, step, True
        user.enroll_code_hash = user.enroll_code_expires = None  # usage unique
        audit.record(db, user.username, "auth.enroll_done", "user", user.id)
        out = promote(db, s, user, response, ip, "enrollment")
        return {**out, "recovery_codes": plain}  # affichés une seule fois

    @app.post("/api/v1/auth/totp")
    def totp(body: TotpIn, request: Request, response: Response, db: DbSession = Depends(get_db)):
        ip = client_ip(request)
        s = _session_from_cookie(request, db)
        if s is None or s.stage != "password":
            raise HTTPException(401, "Étape mot de passe requise.")
        user = db.get(User, s.user_id)
        if user is None or not user.active:
            raise HTTPException(401, "Étape mot de passe requise.")
        if not login_ip_limiter.allow(ip, db) or not login_user_limiter.allow(user.username.lower(), db):
            raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
        if not user.enrolled:
            raise HTTPException(401, "Enrôlement de la double authentification requis.")
        if sso_only(user):  # SSO imposé pendant qu'une session intermédiaire existait encore
            db.delete(s)
            audit.record(db, user.username, "auth.local_login_refused", "user", user.id, None, {"ip": ip, "etape": "totp"})
            commit(db)
            raise HTTPException(403, SSO_ONLY_ERROR)
        if user.locked_until and as_utc(user.locked_until) > utcnow():
            # Verrouillé : aucune session intermédiaire ne doit permettre de continuer.
            db.execute(delete(Session).where(Session.user_id == user.id, Session.stage == "password"))
            audit.record(db, user.username, "auth.totp_while_locked", "user", user.id, None, {"ip": ip})
            commit(db)
            raise HTTPException(401, GENERIC_LOGIN_ERROR)
        ok, method = False, None
        if body.code:
            step = security.verify_totp(box.decrypt(user.totp_secret, f"totp:{user.id}"), body.code,
                                        user.last_totp_step)
            if step is not None:
                user.last_totp_step, ok, method = step, True, "totp"
        elif body.recovery_code:
            remaining = security.use_recovery_code(user.recovery_codes or [], body.recovery_code)
            if remaining is not None:
                user.recovery_codes, ok, method = remaining, True, "recovery_code"
        if not ok:
            count_second_factor_failure(db, user, ip)
            raise HTTPException(401, "Code de vérification invalide.")
        return promote(db, s, user, response, ip, method)

    @app.post("/api/v1/auth/logout")
    def logout(request: Request, response: Response, user: User = Depends(current_user),
               db: DbSession = Depends(get_db)):
        s = _session_from_cookie(request, db)
        redirect = None
        if s:
            if s.sso_provider and s.sso_id_token and getattr(ctx, "sso_logout_url", None):
                # Déconnexion unique : la session du fournisseur d'identité se ferme aussi (OIDC RP-Initiated Logout)
                try:
                    redirect = ctx.sso_logout_url(s.sso_provider, box.decrypt(s.sso_id_token, f"sso:{s.token_hash}"))
                except Exception:  # noqa: BLE001 - la déconnexion locale ne doit jamais échouer
                    log.exception("Déconnexion unique impossible")
            db.delete(s)
        audit.record(db, user.username, "auth.logout", "user", user.id, None, {"sso": bool(redirect)})
        commit(db)
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(CSRF_COOKIE, path="/")
        return {"status": "ok", "redirect": redirect}

    @app.get("/api/v1/me")
    def me(request: Request, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        s = _session_from_cookie(request, db)
        return {"username": user.username, "display_name": user.display_name, "role": user.role,
                "csrf_token": s.csrf_token if s else None,
                # « virustotal » : interrupteur d'instance ET rôle de l'équipe (ADR-0022) ; faux pour le client et l'Admin,
                # l'interface ne leur montre alors rien de cette fonction.
                "features": {"timestamping": bool(settings.tsa_url),
                             "virustotal": bool(settings.virustotal_enabled and user.role in ("analyst", "manager"))},
                # Session ouverte par SSO : la double authentification est alors celle du fournisseur d'identité, que
                # Keryx ne constate pas lui-même (l'interface n'affiche « 2FA active » que pour une session locale).
                "sso": bool(s and s.sso_provider),
                "clients": [{"key": t.key, "name": t.name} for t in user.tenants]}

    # ---------------------------------------------------------------- ingestion Wazuh
    def _auth_ingest_key(authorization: str | None, ip: str) -> tuple[str, str, str]:
        db = SessionLocal()
        try:
            key = None
            if authorization and authorization.startswith("Bearer ") and len(authorization) < 200:
                key = db.scalars(select(ApiKey).where(
                    ApiKey.key_hash == security.sha256(authorization[7:].strip()))).first()
            if key is None or key.revoked:
                # Limite AVANT d'écrire dans l'audit : un inconnu ne peut pas remplir le journal.
                if ingest_fail_limiter.allow(ip, db):
                    audit.record(db, "anonyme", "ingest.rejected_key", None, None, None, {"ip": ip})
                    commit(db)
                    raise HTTPException(401, "Clé d'API invalide.")
                raise HTTPException(429, "Trop de tentatives, réessayez plus tard.")
            if not ingest_limiter.allow(key.id, db):
                raise HTTPException(429, "Débit d'ingestion dépassé.")
            key.last_used_at = utcnow()
            db.commit()
            return key.id, key.tenant_id, key.name
        finally:
            db.close()

    def _ingest_sync(raw: bytes, tenant_id: str, key_name: str) -> JSONResponse:
        try:
            alert = json.loads(raw, parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise HTTPException(400, "Le corps n'est pas un JSON valide.")
        db = SessionLocal()
        try:
            tenant = db.get(Tenant, tenant_id)
            try:
                result = ingest_alert(db, settings, tenant, alert, actor=f"wazuh:{key_name}")
            except AlertRejected as exc:
                db.rollback()
                raise HTTPException(422, str(exc))
            notif_ids = [n.id for n in result.notifications if n.status == "en_attente"]
            commit(db)
            if result.status == "ignored":
                return JSONResponse({"status": "ignored", "reason": result.reason}, status_code=202)
            return JSONResponse(
                {"status": result.status, "ticket": result.ticket.ref, "occurrences": result.ticket.occurrences},
                status_code=201 if result.status == "created" else 200,
                background=BackgroundTask(send_pending, SessionLocal, settings, notif_ids) if notif_ids else None,
            )
        finally:
            db.close()

    @app.post("/api/v1/ingest/wazuh")
    async def ingest(request: Request, authorization: str | None = Header(default=None)):
        ip = client_ip(request)
        # Authentification avant de lire le corps ; accès base hors de la boucle d'événements.
        _key_id, tenant_id, key_name = await run_in_threadpool(_auth_ingest_key, authorization, ip)
        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > settings.max_alert_bytes):
            raise HTTPException(413, "Alerte trop volumineuse.")
        raw = bytearray()
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > settings.max_alert_bytes:
                raise HTTPException(413, "Alerte trop volumineuse.")
        return await run_in_threadpool(_ingest_sync, bytes(raw), tenant_id, key_name)

    # ---------------------------------------------------------------- tickets
    def ticket_summary(t: Ticket, tenants: dict[str, Tenant], users: dict[str, User] | None = None,
                       with_sla: bool = True) -> dict[str, Any]:
        out = _ticket_summary(t, tenants, users)
        if with_sla:  # échéances internes : jamais montrées au client
            out.update(sla_state(t, tenants.get(t.tenant_id)))
        return out

    def _ticket_summary(t: Ticket, tenants: dict[str, Tenant], users: dict[str, User] | None = None) -> dict[str, Any]:
        return {
            "ref": t.ref, "title": t.title,
            "client": tenants[t.tenant_id].name if t.tenant_id in tenants else None,
            "client_key": tenants[t.tenant_id].key if t.tenant_id in tenants else None,
            "status": t.status, "criticite_initiale": t.criticite_initiale, "gravite": t.gravite,
            "tlp": t.tlp, "mitre": [m["id"] for m in t.mitre], "mitre_source": t.mitre_source,
            "occurrences": t.occurrences, "detected_at": rfc3339(t.detected_at),
            "last_seen_at": rfc3339(t.last_seen_at),
            "assignee": (users or {}).get(t.assignee_id).display_name if users and t.assignee_id in users else None,
            "rex_en_attente": rex_pending(t.status, t.rex_required), "crisis": t.crisis,
        }

    @app.get("/api/v1/tickets")
    def list_tickets(status: str | None = Query(default=None, max_length=200), client: str | None = None,
                     rex_en_attente: bool = False,
                     q: str | None = Query(default=None, max_length=200), assignee: str | None = None,
                     overdue: bool = False, crisis: bool = False, severity: str | None = Query(default=None, max_length=20),
                     sort: str = "created", order: str = "desc",
                     limit: int = 100, offset: int = 0,
                     user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """File des tickets. `status` accepte plusieurs statuts séparés par des virgules (« à qualifier » = nouveau et
        en évaluation) ; `severity` filtre sur la gravité qualifiée ou, à défaut, sur la criticité initiale ; les tris
        `criticite` et `gravite` suivent l'ordre métier Critique > Élevée > Moyenne > Faible, pas l'ordre alphabétique."""
        limit, offset = max(1, min(limit, 500)), max(0, offset)
        if user.role == "admin":
            raise HTTPException(403, "Le rôle Admin n'a pas accès au contenu des tickets.")
        tenants = {t.id: t for t in user.tenants}
        ids = list(tenants)
        if client:
            ids = [i for i, t in tenants.items() if t.key == client.upper()]
        # Rang d'une gravité : Faible = 1 … Critique = 4 ; 0 quand elle n'est pas encore fixée (gravité avant qualification).
        rank = lambda col: case({s: i for i, s in enumerate(SEVERITIES, start=1)}, value=col, else_=0)  # noqa: E731
        sort_cols = {"created": Ticket.created_at, "updated": Ticket.updated_at, "detected": Ticket.detected_at,
                     "ref": Ticket.seq, "status": Ticket.status, "occurrences": Ticket.occurrences,
                     "criticite": rank(Ticket.criticite_initiale), "gravite": rank(Ticket.gravite)}
        if sort not in sort_cols or order not in ("asc", "desc"):
            raise HTTPException(422, f"Tri attendu parmi : {', '.join(sort_cols)} ; ordre asc ou desc.")
        if severity and severity not in SEVERITIES:
            raise HTTPException(422, f"Gravité attendue parmi : {', '.join(SEVERITIES)}.")
        col = sort_cols[sort]
        query = select(Ticket).where(Ticket.tenant_id.in_(ids)).order_by(col.asc() if order == "asc" else col.desc(),
                                                                       Ticket.id.desc())
        statuses = [s.strip() for s in (status or "").split(",") if s.strip()]
        if statuses:
            query = query.where(Ticket.status.in_(statuses))
        if severity:
            query = query.where(func.coalesce(Ticket.gravite, Ticket.criticite_initiale) == severity)
        if rex_en_attente:
            query = query.where(Ticket.status == "cloture", Ticket.rex_required.is_(True))
        if crisis:
            query = query.where(Ticket.crisis.is_(True))
        if assignee == "me":
            query = query.where(Ticket.assignee_id == user.id)
        elif assignee == "none":
            query = query.where(Ticket.assignee_id.is_(None))
        elif assignee:
            aid = db.scalar(select(User.id).where(User.username == assignee[:120]))
            query = query.where(Ticket.assignee_id == aid) if aid else query.where(false())
        if q and q.strip():
            like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            fields = [Ticket.ref, Ticket.title, Ticket.rule_description, Ticket.rule_id, Ticket.agent_name, Ticket.agent_ip]
            conds = [f.ilike(like, escape="\\") for f in fields]
            # Les commentaires internes ne comptent que pour les agents du SOC (jamais pour le client).
            cq = select(Comment.ticket_id).where(Comment.body_html.ilike(like, escape="\\"))
            if user.role == "client":
                cq = cq.where(Comment.visible_client.is_(True))
            conds.append(Ticket.id.in_(cq))
            query = query.where(or_(*conds))
        if overdue and user.role != "client":
            open_t = [t for t in db.scalars(query).all() if sla_state(t, tenants.get(t.tenant_id))["overdue"]]
            total, tickets = len(open_t), open_t[offset:offset + limit]
        else:
            total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
            tickets = db.scalars(query.limit(limit).offset(offset)).all()
        assignee_ids = {t.assignee_id for t in tickets if t.assignee_id}
        users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(assignee_ids)))} if assignee_ids else {}
        audit.record(db, user.username, "ticket.list", None, None, None, {"count": len(tickets)})
        commit(db)
        return {"items": [ticket_summary(t, tenants, users, with_sla=user.role != "client") for t in tickets],
                "limit": limit, "offset": offset,
                "total": total}

    @app.get("/api/v1/tickets/counts")
    def ticket_counts(client: str | None = Query(default=None, max_length=16),
                      user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Compteurs de la file pour l'équipe (cartes de synthèse) : tickets par statut, tickets ouverts par gravité
        (qualifiée ou, à défaut, criticité initiale), en retard, retours d'expérience en attente. Mêmes clients que la
        liste [PDIS IV.3.8.g]. Ce ne sont que des nombres : le relevé périodique de la file n'ajoute pas d'entrée au
        journal d'audit ; la lecture de la liste, elle, reste tracée (`ticket.list`)."""
        require_role(user, "analyst", "manager")   # ni l'Admin (aucun accès aux tickets), ni le client (pas d'échéances internes)
        tenants = {t.id: t for t in user.tenants}
        ids = [i for i, t in tenants.items() if not client or t.key == client.upper()]
        mine = Ticket.tenant_id.in_(ids)
        open_statuses = ("nouveau", "en_evaluation", "en_reponse")
        by_status = dict(db.execute(select(Ticket.status, func.count()).where(mine).group_by(Ticket.status)).all())
        severity = func.coalesce(Ticket.gravite, Ticket.criticite_initiale)
        by_severity = dict(db.execute(select(severity, func.count()).where(mine, Ticket.status.in_(open_statuses))
                                      .group_by(severity)).all())
        rex = db.scalar(select(func.count()).select_from(Ticket).where(mine, Ticket.status == "cloture",
                                                                       Ticket.rex_required.is_(True))) or 0
        overdue = sum(1 for t in db.scalars(select(Ticket).where(mine, Ticket.status.in_(open_statuses)))
                      if sla_state(t, tenants.get(t.tenant_id))["overdue"])
        return {"total": sum(by_status.values()), "by_status": {s: by_status.get(s, 0) for s in STATUSES},
                "open_by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
                "overdue": overdue, "rex_en_attente": rex}

    def attachment_view(a: Attachment) -> dict:
        return {"id": a.id, "kind": a.kind, "filename": a.filename, "content_type": a.content_type, "size": a.size,
                "sha256": a.sha256, "description": a.description, "collected_at": rfc3339(a.collected_at),
                "method": a.method, "sensitivity": a.sensitivity, "location": a.location,
                "scan_status": a.scan_status, "scan_detail": a.scan_detail, "lifecycle": a.lifecycle,
                "visible_client": a.visible_client, "created_at": rfc3339(a.created_at)}

    @app.get("/api/v1/tickets/{ref}")
    def get_ticket(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        t = load_ticket(db, user, ref)
        is_client = user.role == "client"
        comments = db.scalars(select(Comment).where(Comment.ticket_id == t.id).order_by(Comment.created_at)).all()
        events = db.scalars(select(TicketEvent).where(TicketEvent.ticket_id == t.id).order_by(TicketEvent.ts)).all()
        atts = db.scalars(select(Attachment).where(Attachment.ticket_id == t.id).order_by(Attachment.created_at)).all()
        author_ids = {c.author_id for c in comments} | ({t.assignee_id} if t.assignee_id else set())
        authors = {u.id: u for u in db.scalars(select(User).where(User.id.in_(author_ids)))} if author_ids else {}
        out = ticket_summary(t, {x.id: x for x in user.tenants}, authors, with_sla=not is_client)
        out.update({
            "body_html": t.body_html, "verdict": t.verdict, "dommages": t.dommages, "importance": t.importance,
            "impact": t.impact, "risque": t.risque, "rex_required": t.rex_required,
            "rule": {"id": t.rule_id, "level": t.rule_level, "description": t.rule_description, "groups": t.rule_groups},
            "agent": {"id": t.agent_id, "name": t.agent_name, "ip": t.agent_ip},
            "mitre_detail": t.mitre, "classification": t.classification,
            "isi": t.isi if not is_client else None,
            "attachment_max_mb": db.get(Tenant, t.tenant_id).max_attachment_mb or 20,
            "severity_hint": {d: gravite(d, t.importance, db.get(Tenant, t.tenant_id).severity_grid) for d in DOMMAGES}
            if not is_client else None,
            "comments": [
                {"author": authors[c.author_id].display_name if c.author_id in authors else "?",
                 "body_html": c.body_html, "visible_client": c.visible_client, "created_at": rfc3339(c.created_at)}
                for c in comments if (c.visible_client or not is_client)
            ],
            "events": [
                {"ts": rfc3339(e.ts), "actor": e.actor, "action": e.action, "details": e.details}
                for e in events if (e.visible_client or not is_client)
            ],
            "attachments": [attachment_view(a) for a in atts if (a.visible_client or not is_client)],
        })
        if not is_client:
            # Identifiant de l'assigné (le nom affiché n'est pas unique) : sert au sélecteur d'affectation de l'équipe.
            assignee = authors.get(t.assignee_id) if t.assignee_id else None
            out["assignee_username"] = assignee.username if assignee else None
            out["assignee_active"] = bool(assignee and assignee.active)
            out["raw_alerts"] = len(db.scalars(select(RawAlert.id).where(RawAlert.ticket_id == t.id)).all())
            out["synthese"] = {"compromission_initiale": rfc3339(t.compromission_initiale),
                               "chronologie": t.chronologie, "mode_operatoire": t.mode_operatoire,
                               "perimetre": t.perimetre, "rex_html": t.rex_html}
            # Contexte Wazuh (ADR-0021) : lien vers l'alerte et lecture de l'indexeur, pour l'équipe seulement. La clé
            # est absente pour le client, et absente pour tous tant que rien n'est réglé pour ce client.
            wazuh = wazuh_context.ticket_view(db, t, db.get(Tenant, t.tenant_id))
            if wazuh:
                out["wazuh"] = wazuh
            # Recherches VirusTotal déjà faites sur ce ticket (ADR-0022) : pour l'équipe seulement. La clé est absente
            # pour le client, et absente pour tous quand la fonction est coupée sur l'instance.
            if settings.virustotal_enabled:
                out["virustotal"] = routes_virustotal.ticket_view(db, t)
        audit.record(db, user.username, "ticket.read", "ticket", t.ref, t.tenant_id)
        commit(db)
        return out

    @app.post("/api/v1/tickets/{ref}/qualification")
    def qualify(ref: str, body: QualificationIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        require_open(t)
        sent = body.model_fields_set  # mise à jour partielle : un champ absent n'efface rien
        if "verdict" in sent and body.verdict not in VERDICTS:
            raise HTTPException(422, f"Verdict attendu parmi : {', '.join(VERDICTS)}.")
        if "importance" in sent and body.importance not in IMPORTANCES:
            raise HTTPException(422, f"Importance attendue parmi : {', '.join(IMPORTANCES)}.")
        if "dommages" in sent and body.dommages not in DOMMAGES:
            raise HTTPException(422, f"Dommages attendus parmi : {', '.join(DOMMAGES)}.")
        if "tlp" in sent and body.tlp not in TLP:
            raise HTTPException(422, f"Marquage attendu parmi : {', '.join(TLP)}.")
        if "verdict" in sent and body.verdict != t.verdict and t.status not in ("nouveau", "en_evaluation"):
            raise HTTPException(409, "Le verdict ne peut changer qu'en phase d'évaluation.")
        for f in ("verdict", "importance", "dommages", "impact", "risque", "tlp"):
            if f in sent:
                setattr(t, f, getattr(body, f))
        if t.dommages:  # toujours recalculée sur l'état complet
            tenant = db.get(Tenant, t.tenant_id)
            t.gravite = gravite(t.dommages, t.importance, tenant.severity_grid)
        t.rex_required = bool(t.verdict and t.verdict != "faux_positif"
                              and is_rex_required(t.gravite or t.criticite_initiale))
        t.qualified_at = t.updated_at = utcnow()
        details = {"verdict": t.verdict, "gravite": t.gravite, "dommages": t.dommages, "importance": t.importance,
                   "tlp": t.tlp}
        event(db, t, user, "qualification", details)
        commit(db)
        return {"ref": t.ref, "verdict": t.verdict, "gravite": t.gravite, "rex_required": t.rex_required}

    @app.post("/api/v1/tickets/{ref}/status")
    def change_status(ref: str, body: StatusIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        try:
            check_transition(t.status, body.status, t.verdict, t.rex_required, t.rex_html)
        except TransitionError as exc:
            raise HTTPException(409, str(exc))
        old, t.status = t.status, body.status
        t.updated_at = utcnow()
        if body.status in ("faux_positif", "cloture"):
            t.closed_at = t.updated_at
        event(db, t, user, "statut", {"from": old, "to": body.status}, visible_client=True)
        commit(db)
        return {"ref": t.ref, "status": t.status, "rex_required": t.rex_required}

    def assign_ticket(db: DbSession, user: User, t: Ticket, target: User | None) -> None:
        t.assignee_id = target.id if target else None
        t.updated_at = utcnow()
        event(db, t, user, "affectation", {"assignee": target.username if target else None})
        if target is not None and target.id != user.id:
            inbox.push(db, target, "assignation", t.ref, actor=user.username)

    @app.post("/api/v1/tickets/{ref}/assign")
    def assign(ref: str, body: AssignIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        require_open(t)
        target = None
        if body.username:
            target = db.scalars(select(User).where(User.username == body.username)).first()
            if (target is None or not target.active or target.role not in ("analyst", "manager")
                    or t.tenant_id not in [x.id for x in target.tenants]):
                raise HTTPException(422, "Utilisateur inconnu ou non affecté à ce client.")
        assign_ticket(db, user, t, target)
        commit(db)
        return {"ref": t.ref, "assignee": target.display_name if target else None,
                "assignee_username": target.username if target else None}

    @app.get("/api/v1/tickets/{ref}/assignables")
    def assignables(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        tenant = db.get(Tenant, t.tenant_id)
        users = db.scalars(select(User).where(User.role.in_(("analyst", "manager")), User.active.is_(True))).all()
        return {"items": [{"username": u.username, "display_name": u.display_name}
                          for u in users if tenant in u.tenants]}

    def reveal_embedded_images(db: DbSession, t: Ticket, user: User, html: str, origine: str) -> None:
        """Images insérées depuis l'éditeur : déposées sans visibilité client, elles ne deviennent visibles qu'ici, quand
        un contenu montré au client (commentaire visible, description) les référence. La visibilité est donc décidée par
        le serveur à l'enregistrement du contenu, jamais par l'état d'une case au moment du dépôt. Un client ne peut pas
        rendre visible une pièce interne en citant son adresse ; une pièce d'un autre ticket n'est jamais concernée."""
        if user.role not in ("analyst", "manager"):
            return
        ids = set(EMBEDDED_ATTACHMENT.findall(html or ""))
        if not ids:
            return
        rows = db.scalars(select(Attachment).where(
            Attachment.id.in_(ids), Attachment.ticket_id == t.id, Attachment.kind == "image",
            Attachment.visible_client.is_(False), Attachment.scan_status != "quarantaine")).all()
        for a in rows:
            a.visible_client = True
            db.add(CustodyEvent(attachment_id=a.id, actor=user.username, action="visible_client", reason=origine))
            event(db, t, user, "piece_jointe_visible", {"id": a.id, "sha256": a.sha256, "origine": origine},
                  visible_client=True)

    def notify_comment(db: DbSession, t: Ticket, author: User, html: str, visible: bool) -> None:
        """Mentions @identifiant (agents du SOC affectés au client) et réponse d'un client à l'équipe."""
        plain = re.sub(r"<[^>]+>", " ", html)
        names = {m.lower() for m in re.findall(r"(?<![\w.@-])@([A-Za-z0-9][A-Za-z0-9._-]{2,63})", plain)}
        if names:
            for u in db.scalars(select(User).where(func.lower(User.username).in_(names), User.active.is_(True),
                                                   User.role.in_(("analyst", "manager")))).all():
                if u.id != author.id and t.tenant_id in [x.id for x in u.tenants]:
                    inbox.push(db, u, "mention", t.ref, actor=author.username)
        if author.role == "client":
            assignee = db.get(User, t.assignee_id) if t.assignee_id else None
            # L'assigné doit pouvoir lire la réponse : actif, toujours agent du SOC, toujours affecté à ce client.
            # Sinon (compte désactivé, rôle ou affectation changés, ticket non assigné) : repli sur l'équipe du client.
            reachable = bool(assignee and assignee.active and assignee.role in ("analyst", "manager")
                             and t.tenant_id in [x.id for x in assignee.tenants])
            targets = [assignee] if reachable else [
                u for u in db.scalars(select(User).where(User.role.in_(("analyst", "manager")),
                                                         User.active.is_(True))).all()
                if t.tenant_id in [x.id for x in u.tenants]]
            for u in targets:
                inbox.push(db, u, "reponse_client", t.ref, actor=author.username)

    @app.post("/api/v1/tickets/{ref}/comments", status_code=201)
    def add_comment(ref: str, body: CommentIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        t = load_ticket(db, user, ref)
        require_open(t)  # ticket clos : plus d'échanges (rouvrir ou ouvrir un nouveau ticket)
        visible = True if user.role == "client" else body.visible_client
        clean = clean_html(body.body_html)
        if not clean.strip():
            raise HTTPException(422, "Commentaire vide.")
        db.add(Comment(ticket_id=t.id, author_id=user.id, body_html=clean, visible_client=visible))
        audit.record(db, user.username, "ticket.comment", "ticket", t.ref, t.tenant_id, {"visible_client": visible})
        if visible:  # un commentaire interne ne rend jamais visibles les images qu'il contient
            reveal_embedded_images(db, t, user, clean, "commentaire visible par le client")
        notify_comment(db, t, user, clean, visible)
        commit(db)
        return {"ref": t.ref, "visible_client": visible, "body_html": clean}

    @app.put("/api/v1/tickets/{ref}/body")
    def set_body(ref: str, body: BodyIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        require_open(t)
        previous = t.body_html
        t.body_html = clean_html(body.body_html)
        t.updated_at = utcnow()
        # Historique : la version précédente est conservée dans le registre des actions.
        # Taille bornée : au-delà de 20 000 caractères, l'empreinte et la longueur de la version complète
        # restent tracées (le registre d'audit et la base ne grossissent pas de 200 ko à chaque modification).
        kept = previous if len(previous or "") <= MAX_VERSION_CHARS else (previous or "")[:MAX_VERSION_CHARS]
        event(db, t, user, "description", {
            "version_precedente": kept,
            "version_precedente_sha256": hashlib.sha256((previous or "").encode("utf-8")).hexdigest(),
            "version_precedente_longueur": len(previous or ""),
            "tronquee": len(previous or "") > MAX_VERSION_CHARS,
        })
        reveal_embedded_images(db, t, user, t.body_html, "description du ticket")  # la description est lue par le client
        commit(db)
        return {"ref": t.ref, "body_html": t.body_html}

    @app.put("/api/v1/tickets/{ref}/synthese")
    def set_synthese(ref: str, body: SyntheseIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Synthèse évolutive de l'incident et retour d'expérience [PRIS VI.5.3.e, ISO 27002 5.27]."""
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        if t.status in ("faux_positif", "retour_experience"):
            raise HTTPException(409, "Ticket clos : modification impossible.")
        sent = body.model_fields_set
        for f in ("chronologie", "mode_operatoire", "perimetre", "rex_html"):
            if f in sent:
                v = getattr(body, f)
                setattr(t, f, clean_html(v) if v else None)
        if "compromission_initiale" in sent:
            t.compromission_initiale = input_date(body.compromission_initiale, "Date de compromission initiale")
        t.updated_at = utcnow()
        event(db, t, user, "synthese", {"champs": sorted(sent)})
        commit(db)
        return {"ref": t.ref, "status": "ok"}

    @app.post("/api/v1/tickets/{ref}/mitre")
    def set_mitre(ref: str, body: MitreIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        require_open(t)
        bad = [x for x in body.techniques if not valid_technique(x)]
        if bad:
            raise HTTPException(422, f"Identifiants MITRE invalides : {', '.join(bad[:5])}")
        if db.scalar(select(func.count()).select_from(MitreTechnique)):  # référentiel importé : on s'y fie
            known_ids = set(db.scalars(select(MitreTechnique.technique_id).where(MitreTechnique.technique_id.in_(body.techniques))))
            unknown = [x for x in dict.fromkeys(body.techniques) if x not in known_ids]
            if unknown:
                raise HTTPException(422, f"Technique inconnue du référentiel ATT&CK importé : {', '.join(unknown[:5])}")
        before = [m["id"] for m in t.mitre]
        known = {m["id"]: m for m in t.mitre}  # on garde nom et tactiques déjà connus
        ref = {r.technique_id: r for r in db.scalars(select(MitreTechnique).where(MitreTechnique.technique_id.in_(body.techniques)))}
        t.mitre = [known.get(x) or {"id": x, "technique": ref[x].name if x in ref else "",
                                    "tactics": ref[x].tactics if x in ref else []}
                   for x in dict.fromkeys(body.techniques)]
        t.mitre_source = "manuel"
        t.updated_at = utcnow()
        event(db, t, user, "mitre_manuel", {"avant": before, "apres": [m["id"] for m in t.mitre]})
        commit(db)
        return {"ref": t.ref, "mitre": [m["id"] for m in t.mitre], "mitre_source": "manuel"}

    @app.get("/api/v1/tickets/{ref}/iodef")
    def export_iodef(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Export inspiré d'IODEF v2 en JSON (RFC 7970 / RFC 8727). Sous-ensemble ; schéma complet à valider."""
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        tenant = db.get(Tenant, t.tenant_id)
        node: dict[str, Any] = {"NodeName": [t.agent_name] if t.agent_name else []}
        if t.agent_ip:
            try:
                ip = ipaddress.ip_address(t.agent_ip)
                node["Address"] = [{"value": str(ip), "category": "ipv6-addr" if ip.version == 6 else "ipv4-addr"}]
            except ValueError:
                pass
        doc = {
            "version": "2.0", "lang": "fr",
            "Incident": [{
                "purpose": "reporting", "status": t.status,
                "IncidentID": {"id": t.ref, "name": "keryx"},
                "GenerationTime": rfc3339(utcnow()), "DetectTime": rfc3339(t.detected_at),
                "ReportTime": rfc3339(t.created_at),
                "Description": [t.title],
                "Assessment": [{"Impact": [{"severity": t.gravite or t.criticite_initiale,
                                            "description": t.impact or ""}]}],
                "Contact": [{"role": "creator", "type": "organization", "ContactName": ["Keryx"]},
                            {"role": "cc", "type": "organization", "ContactName": [tenant.name]}],
                "Method": [{"Reference": [{"ReferenceName": {"ID": m["id"]},
                                           "URL": [f"https://attack.mitre.org/techniques/{m['id'].replace('.', '/')}/"]}]}
                           for m in t.mitre],
                "EventData": [{"System": [{"category": "target", "Node": [node]}]}],
                "AdditionalData": [{"dtype": "string", "meaning": "tlp", "value": t.tlp}],
            }],
        }
        problems = iodef_validate(doc)
        if problems:  # ne jamais émettre un document non conforme
            log.error("Export IODEF non conforme pour %s : %s", t.ref, problems)
            raise HTTPException(500, "Export IODEF non conforme à la structure attendue.")
        audit.record(db, user.username, "ticket.export_iodef", "ticket", t.ref, t.tenant_id)
        commit(db)
        return doc

    # ---------------------------------------------------------------- pièces jointes et preuves
    @app.post("/api/v1/tickets/{ref}/attachments", status_code=201)
    def upload_attachment(ref: str, request: Request, file: UploadFile = File(...),
                          description: str = Form(min_length=3, max_length=5000),
                          collected_at: datetime = Form(...), method: str = Form(min_length=3, max_length=500),
                          sensitivity: str = Form("TLP:AMBER"), visible_client: bool = Form(False),
                          embedded: bool = Form(False),
                          user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        t = load_ticket(db, user, ref)
        require_open(t)  # chaîne de possession figée sur un ticket clos [ISO/IEC 27037]
        collected_at = input_date(collected_at, "Date de collecte")
        if embedded:
            # Image insérée depuis l'éditeur : jamais visible au dépôt ; elle le devient à l'enregistrement d'un contenu
            # visible qui la référence (voir reveal_embedded_images). Le dépôt d'un client reste visible par le client.
            visible_client = False
        if sensitivity not in TLP:
            raise HTTPException(422, f"Sensibilité attendue parmi : {', '.join(TLP)}.")
        declared = request.headers.get("content-length")
        if not (declared and declared.isdigit()):
            # Sans Content-Length (envoi chunked), le corps serait entièrement écrit sur disque avant tout contrôle.
            raise HTTPException(411, "En-tête Content-Length obligatoire pour déposer une pièce.")
        tenant = db.get(Tenant, t.tenant_id)
        limit = min(settings.max_attachment_bytes, (tenant.max_attachment_mb or 20) * 1024 * 1024)
        if int(declared) > limit + 64 * 1024:
            raise HTTPException(413, f"Fichier trop volumineux ({limit // (1024 * 1024)} Mo maximum) : déclarer une preuve externe.")
        data = file.file.read(limit + 1)
        try:
            prepared = att.prepare(data, settings, limit)
        except att.AttachmentRejected as exc:
            raise HTTPException(413 if "volumineux" in str(exc) else 422, str(exc))
        status, detail = att.scan(prepared.content, settings)
        quarantined = status == "quarantaine"
        try:
            storage = att.store(settings, prepared.content, quarantined)
        except StorageError as exc:
            log.error("Stockage des pièces : %s", exc)
            raise HTTPException(502, "Le stockage des pièces est indisponible : la pièce n'a pas été enregistrée.")
        try:
            return _record_attachment(db, t, user, file, prepared, storage, status, detail, quarantined,
                                      description, collected_at, method, sensitivity, visible_client)
        except BaseException:
            att.destroy(settings, storage, quarantined)  # pas de fichier orphelin si la base échoue
            raise

    def _record_attachment(db, t, user, file, prepared, storage, status, detail, quarantined,
                           description, collected_at, method, sensitivity, visible_client):
        a = Attachment(
            ticket_id=t.id, tenant_id=t.tenant_id, kind=prepared.kind,
            filename=att.safe_filename(file.filename or "fichier"), storage_name=storage,
            content_type=prepared.content_type, size=len(prepared.content), sha256=prepared.sha256,
            description=description, collected_at=collected_at, method=method, sensitivity=sensitivity,
            scan_status=status, scan_detail=detail,
            visible_client=True if user.role == "client" else visible_client, uploaded_by=user.id,
        )
        db.add(a)
        db.flush()
        reason = f"empreinte reçue {prepared.original_sha256}" if prepared.original_sha256 != prepared.sha256 else ""
        db.add(CustodyEvent(attachment_id=a.id, actor=user.username, action="depot", reason=reason))
        event(db, t, user, "piece_jointe", {"id": a.id, "fichier": a.filename, "sha256": a.sha256,
                                            "antivirus": status}, visible_client=a.visible_client)
        commit(db)
        return attachment_view(a)

    @app.post("/api/v1/tickets/{ref}/preuves-externes", status_code=201)
    def external_evidence(ref: str, body: ExternalEvidenceIn, user: User = Depends(current_user),
                          db: DbSession = Depends(get_db)):
        """Preuve de plus de 20 Mo conservée hors de Keryx (support hors ligne) [PRIS VI.2.4]."""
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        require_open(t)
        if body.sensitivity not in TLP:
            raise HTTPException(422, f"Sensibilité attendue parmi : {', '.join(TLP)}.")
        body.collected_at = input_date(body.collected_at, "Date de collecte")
        a = Attachment(ticket_id=t.id, tenant_id=t.tenant_id, kind="preuve_externe",
                       filename=att.safe_filename(body.filename), storage_name=None, size=body.size,
                       sha256=body.sha256, description=body.description, collected_at=body.collected_at,
                       method=body.method, sensitivity=body.sensitivity, location=body.location,
                       scan_status="non_analyse", uploaded_by=user.id)
        db.add(a)
        db.flush()
        db.add(CustodyEvent(attachment_id=a.id, actor=user.username, action="declaration", reason=body.location))
        event(db, t, user, "preuve_externe", {"id": a.id, "sha256": a.sha256, "lieu": a.location})
        commit(db)
        return attachment_view(a)

    @app.get("/api/v1/attachments/{attachment_id}/content")
    def download_attachment(attachment_id: str, request: Request, motif: str | None = None,
                            confirmer_malveillant: bool = False, x_csrf_token: str | None = Header(default=None),
                            user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        a, t = load_attachment(db, user, attachment_id)
        if a.kind != "image" or a.scan_status == "quarantaine":
            # Un fichier se télécharge par un appel explicite de l'interface (jeton CSRF), jamais par une balise <img> ou
            # un lien glissé dans un contenu : sinon un tiers ferait inscrire un téléchargement, avec le motif de son
            # choix, au nom de qui ouvre le ticket (chaîne de possession, ISO/IEC 27037).
            s = _session_from_cookie(request, db)
            if not s or not x_csrf_token or not security.hmac_equal(x_csrf_token, s.csrf_token):
                raise HTTPException(403, "Jeton CSRF manquant ou invalide.")
        if a.kind == "preuve_externe" or not a.storage_name or a.lifecycle != "conserve":
            raise HTTPException(410, "Contenu non disponible dans Keryx (preuve externe, restituée ou détruite).")
        quarantined = a.scan_status == "quarantaine"
        if quarantined:
            if user.role == "client":
                raise HTTPException(404, "Pièce introuvable.")
            if not confirmer_malveillant or not motif or len(motif) < 3:
                raise HTTPException(409, "Fichier en quarantaine : confirmer le téléchargement et indiquer un motif.")
        if a.kind == "fichier" and (not motif or len(motif) < 3):
            raise HTTPException(422, "Indiquer le motif du téléchargement (chaîne de possession).")
        try:
            data = att.read(settings, a.storage_name, quarantined)
        except FileNotFoundError:
            raise HTTPException(410, "Fichier introuvable sur le stockage : signaler à l'administrateur.")
        except StorageError as exc:
            log.error("Lecture d'une pièce : %s", exc)
            raise HTTPException(502, "Le stockage des pièces est indisponible ou la pièce est altérée : signaler à l'administrateur.")
        db.add(CustodyEvent(attachment_id=a.id, actor=user.username,
                            action="telechargement" if a.kind == "fichier" else "consultation",
                            reason=(motif or "")[:500]))
        audit.record(db, user.username, "attachment.download", "attachment", a.id, a.tenant_id,
                     {"ticket": t.ref, "motif": (motif or "")[:200], "quarantaine": quarantined})
        commit(db)
        inline = a.kind == "image" and not quarantined
        name = a.filename + (".quarantaine.zip" if quarantined else "")
        disposition = ("inline" if inline else "attachment") + f"; filename*=UTF-8''{quote(name)}"
        return Response(content=data, media_type=a.content_type if inline else "application/octet-stream",
                        headers={"Content-Disposition": disposition, "Cache-Control": "no-store",
                                 "Content-Security-Policy": "default-src 'none'; sandbox"})

    @app.get("/api/v1/attachments/{attachment_id}/custody")
    def custody(attachment_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        a, t = load_attachment(db, user, attachment_id)
        rows = db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == a.id).order_by(CustodyEvent.ts)).all()
        out = {"items": [{"ts": rfc3339(c.ts), "actor": c.actor, "action": c.action, "reason": c.reason}
                         for c in rows]}
        # La consultation de la chaîne de possession (qui a touché la pièce, quand, pourquoi) est elle-même tracée.
        audit.record(db, user.username, "attachment.custody_read", "attachment", a.id, a.tenant_id,
                     {"ticket": t.ref, "count": len(rows)})
        commit(db)
        return out

    @app.post("/api/v1/attachments/{attachment_id}/lifecycle")
    def lifecycle(attachment_id: str, body: LifecycleIn, user: User = Depends(current_user),
                  db: DbSession = Depends(get_db)):
        """Restitution (analyste, manager) ou destruction (manager seulement) [PRIS VI.2.4]."""
        require_role(user, "analyst", "manager")
        a, t = load_attachment(db, user, attachment_id)
        if body.lifecycle not in LIFECYCLE or body.lifecycle == "conserve":
            raise HTTPException(422, "Cycle de vie attendu : restitue ou detruit.")
        # conservée → restituée ou détruite ; restituée → détruite (son contenu, resté sur le stockage, doit pouvoir être
        # supprimé) ; une pièce détruite ne change plus d'état.
        if body.lifecycle not in LIFECYCLE_NEXT.get(a.lifecycle, ()):
            raise HTTPException(409, "Cette pièce est déjà détruite." if a.lifecycle == "detruit"
                                else "Cette pièce est déjà restituée : seule sa destruction reste possible.")
        if body.lifecycle == "detruit":
            require_role(user, "manager")
        a.lifecycle = body.lifecycle
        db.add(CustodyEvent(attachment_id=a.id, actor=user.username, action=body.lifecycle, reason=body.reason))
        event(db, t, user, "piece_jointe_" + body.lifecycle, {"id": a.id, "sha256": a.sha256, "motif": body.reason})
        commit(db)
        # Suppression du fichier seulement une fois la destruction enregistrée en base.
        if body.lifecycle == "detruit" and a.storage_name:
            try:
                att.destroy(settings, a.storage_name, a.scan_status == "quarantaine")
            except StorageError as exc:  # la destruction est déjà tracée : l'objet restant est à purger à la main
                log.error("Destruction d'un objet à vérifier (pièce %s) : %s", a.id, exc)
        return attachment_view(a)

    # ---------------------------------------------------------------- administration
    @app.get("/api/v1/audit/verify")
    def audit_verify(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        ok, bad = audit.verify_chain(db)
        count = db.scalar(select(AuditEntry.seq).order_by(AuditEntry.seq.desc()).limit(1)) or 0
        audit.record(db, user.username, "audit.verify", None, None, None, {"ok": ok})
        commit(db)
        return {"chain_ok": ok, "first_broken_seq": bad, "entries": count}

    @app.get("/api/v1/admin/revue-comptes", dependencies=[Depends(admin_guard)])
    def account_review(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Revue des comptes et des droits [PDIS IV.3.4.b, PRIS IV.3.n]."""
        require_role(user, "admin")
        users = db.scalars(select(User).order_by(User.role, User.username)).all()
        audit.record(db, user.username, "admin.account_review", None, None, None, {"count": len(users)})
        commit(db)
        return {"generated_at": rfc3339(utcnow()), "items": [
            {"username": u.username, "display_name": u.display_name, "role": u.role, "active": u.active,
             "clients": [t.key for t in u.tenants], "last_login_at": rfc3339(u.last_login_at),
             "recovery_codes_left": len(u.recovery_codes or []),
             "locked": bool(u.locked_until and as_utc(u.locked_until) > utcnow())} for u in users]}

    # ---------------------------------------------------------------- relance des courriels en échec
    if settings.smtp_host and settings.notify_retry_interval_s > 0:
        def _retry_loop() -> None:  # pragma: no cover - tâche de fond
            while True:
                time.sleep(settings.notify_retry_interval_s)
                try:
                    retry_failed(SessionLocal, settings)
                except Exception:
                    log.exception("Relance des notifications en échec")
        threading.Thread(target=_retry_loop, name="notify-retry", daemon=True).start()

    # ---------------------------------------------------------------- routeurs complémentaires
    ctx = SimpleNamespace(admin_guard=admin_guard,
        settings=settings, box=box, SessionLocal=SessionLocal, get_db=get_db, current_user=current_user,
        require_role=require_role, require_open=require_open, commit=commit, load_ticket=load_ticket,
        visible_tenant_ids=visible_tenant_ids, event=event, session_from_cookie=_session_from_cookie,
        client_ip=client_ip, assign_ticket=assign_ticket, ticket_summary=ticket_summary, promote=promote,
        login_ip_limiter=login_ip_limiter, login_user_limiter=login_user_limiter, sso_only=sso_only,
        count_second_factor_failure=count_second_factor_failure, open_session=open_session,
        set_cookie=_set_cookie, load_attachment=load_attachment, SESSION_COOKIE=SESSION_COOKIE, CSRF_COOKIE=CSRF_COOKIE, oidc_providers=oidc_providers,
        limiter=limiter, attachment_view=attachment_view, input_date=input_date)
    routes_admin.register(app, ctx)
    routes_work.register(app, ctx)
    routes_reports.register(app, ctx)
    routes_ops.register(app, ctx)
    routes_webauthn.register(app, ctx)
    routes_oidc.register(app, ctx)
    routes_timestamp.register(app, ctx)
    routes_isi.register(app, ctx)
    routes_wazuh.register(app, ctx)
    routes_virustotal.register(app, ctx)

    # ---------------------------------------------------------------- interface web
    dist = settings.web_dist
    if os.path.isdir(os.path.join(dist, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(dist, "assets")), name="assets")

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon():
        # Seul fichier statique servi à la racine : le reste des chemins à extension reçoit un 404 (voir ci-dessous).
        path = os.path.join(dist, "favicon.svg")
        if not os.path.isfile(path):
            raise HTTPException(404, "Ressource introuvable.")
        return FileResponse(path, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "Ressource introuvable.")
        # Aucune route de l'interface ne commence par un point ni ne se termine par une extension de fichier : ces
        # chemins (/.git, /.env, /x.php, /backup.zip…) reçoivent un vrai 404, pas la page d'accueil avec un statut 200.
        last = full_path.rsplit("/", 1)[-1]
        if any(seg.startswith(".") for seg in full_path.split("/")) or re.search(r"\.[A-Za-z0-9]{1,8}$", last):
            raise HTTPException(404, "Ressource introuvable.")
        index = os.path.join(dist, "index.html")
        if not os.path.isfile(index):
            raise HTTPException(404, "Interface web non construite (voir web/README).")
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app


def _set_cookie(response: Response, name: str, value: str, settings: Settings, http_only: bool, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=http_only, secure=settings.cookie_secure,
                        samesite="strict", path="/")


def _title(status: int) -> str:
    return {
        400: "Requête incorrecte", 401: "Non authentifié", 403: "Accès refusé", 404: "Introuvable",
        405: "Méthode non autorisée", 409: "Conflit", 410: "Plus disponible", 413: "Contenu trop volumineux",
        422: "Requête invalide", 429: "Trop de requêtes",
    }.get(status, "Erreur")
