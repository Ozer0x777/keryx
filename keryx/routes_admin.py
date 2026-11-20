"""Administration dans l'interface : comptes, clients, clés d'API, table MITRE, profil, état du système.

[PDIS IV.3.4.b revue des comptes ; IV.3.9.d à h séparation administrateur / opérateur ;
PRIS IV.3.n, o ; ISO/IEC 27002 5.15, 5.16, 5.17, 5.18, 8.2] Toutes ces routes sont réservées au rôle Admin
(sauf la table MITRE, ouverte aussi au Manager, et le profil, ouvert à chacun pour son propre compte).
Un Admin ne lit jamais le contenu des tickets : aucune route d'ici n'y donne accès.
"""
from __future__ import annotations

import os
import secrets
import shutil
import socket
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from . import audit, notify, security
from .ids import as_utc, rfc3339, utcnow
from .mitre import valid_technique
from .models import (ROLES, ApiKey, MitreMapping, Notification, Session, Tenant, Ticket, User)

SILENT_KEY_HOURS = 24


class UserCreateIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,64}$")
    display_name: str = Field(min_length=1, max_length=200)
    role: str
    email: str | None = Field(default=None, max_length=254)
    clients: list[str] = Field(default_factory=list, max_length=100)
    password: str = Field(min_length=12, max_length=256)


class UserPatchIn(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    role: str | None = None
    email: str | None = Field(default=None, max_length=254)
    clients: list[str] | None = Field(default=None, max_length=100)
    active: bool | None = None


class PasswordResetIn(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class ClientCreateIn(BaseModel):
    key: str = Field(pattern=r"^[A-Za-z0-9]{1,16}$")
    name: str = Field(min_length=1, max_length=200)


class ClientPatchIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    contact_emails: list[str] | None = Field(default=None, max_length=50)
    severity_grid: dict | None = None
    retention_months: int | None = Field(default=None, ge=6, le=120)  # PDIS IV.2.2.w : 6 mois minimum
    sla: dict | None = None
    max_attachment_mb: int | None = Field(default=None, ge=1, le=20)


class ApiKeyCreateIn(BaseModel):
    client: str = Field(max_length=16)
    name: str = Field(min_length=1, max_length=120)


class MitreIn(BaseModel):
    technique: str = Field(max_length=16)
    name: str = Field(default="", max_length=200)
    tactic: str = Field(default="", max_length=120)
    rule_id: str | None = Field(default=None, max_length=32)
    rule_group: str | None = Field(default=None, max_length=120)


class ChangePasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=12, max_length=256)


class RegenCodesIn(BaseModel):
    password: str = Field(max_length=256)


def _grid_ok(grid: dict) -> bool:
    from .severity import DOMMAGES, IMPORTANCES
    from .models import SEVERITIES
    return all(isinstance(grid.get(d), dict) and all(grid[d].get(i) in SEVERITIES for i in IMPORTANCES)
               for d in DOMMAGES)


def _sla_ok(sla: dict) -> bool:
    from .models import SEVERITIES
    for sev, v in sla.items():
        if sev not in SEVERITIES or not isinstance(v, dict):
            return False
        for k, h in v.items():
            if k not in ("qualification", "resolution") or not isinstance(h, (int, float)) or not 0 < h <= 24 * 365:
                return False
    return True


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit
    settings, box = ctx.settings, ctx.box

    def tenants_by_keys(db: DbSession, keys: list[str]) -> list[Tenant]:
        out = []
        for k in dict.fromkeys(x.strip().upper() for x in keys):
            t = db.scalars(select(Tenant).where(Tenant.key == k)).first()
            if t is None:
                raise HTTPException(422, f"Client inconnu : {k}")
            out.append(t)
        return out

    def check_role_clients(role: str, tenants: list[Tenant]) -> None:
        if role not in ROLES:
            raise HTTPException(422, f"Rôle attendu parmi : {', '.join(ROLES)}.")
        if role == "client" and len(tenants) != 1:
            raise HTTPException(422, "Un compte Client est rattaché à exactement un client.")
        if role == "admin" and tenants:
            raise HTTPException(422, "Un compte Admin n'est rattaché à aucun client (séparation admin / opérateurs).")
        if role in ("analyst", "manager") and not tenants:
            raise HTTPException(422, "Affecter au moins un client à cet utilisateur.")

    def user_view(u: User) -> dict:
        return {"username": u.username, "display_name": u.display_name, "role": u.role, "email": u.email,
                "active": u.active, "enrolled": u.enrolled, "clients": [t.key for t in u.tenants],
                "last_login_at": rfc3339(u.last_login_at), "recovery_codes_left": len(u.recovery_codes or []),
                "locked": bool(u.locked_until and as_utc(u.locked_until) > utcnow())}

    def require_enrollment(u: User) -> None:
        """Le titulaire enrôle lui-même son application TOTP à sa prochaine connexion : l'Admin ne voit jamais
        ce secret (séparation administrateur / opérateur, PDIS IV.3.9.d à h)."""
        u.totp_secret, u.recovery_codes, u.last_totp_step, u.enrolled = "", [], None, False

    def issue_enroll_code(u: User) -> dict:
        """Génère le code d'activation. Envoyé directement au titulaire par courriel quand le SMTP et son adresse
        existent (l'Admin ne le voit alors jamais) ; sinon rendu une fois à l'Admin, qui le transmet hors bande."""
        code = secrets.token_urlsafe(12)
        u.enroll_code_hash = security.sha256(code)
        u.enroll_code_expires = utcnow() + timedelta(hours=72)
        if settings.smtp_host and u.email:
            try:
                notify._send(settings, u.email, "[Keryx] Activation de votre compte",
                             f"Votre code d'activation (valable 72 h) : {code}\n"
                             f"Connexion : {settings.public_url}\n")
                return {"activation": "courriel"}
            except Exception:  # noqa: BLE001 - repli : remise manuelle par l'Admin
                pass
        return {"activation": "administrateur", "enrollment_code": code}

    def drop_sessions(db: DbSession, u: User) -> None:
        db.execute(delete(Session).where(Session.user_id == u.id))

    def get_user(db: DbSession, username: str) -> User:
        u = db.scalars(select(User).where(User.username == username[:120])).first()
        if u is None:
            raise HTTPException(404, "Utilisateur introuvable.")
        return u

    # ---------------------------------------------------------------- comptes
    @app.get("/api/v1/admin/users")
    def users_list(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        return {"items": [user_view(u) for u in db.scalars(select(User).order_by(User.role, User.username))]}

    @app.post("/api/v1/admin/users", status_code=201)
    def users_create(body: UserCreateIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        tenants = tenants_by_keys(db, body.clients)
        check_role_clients(body.role, tenants)
        if db.scalars(select(User).where(User.username == body.username)).first():
            raise HTTPException(409, "Cet identifiant existe déjà.")
        u = User(username=body.username, display_name=body.display_name, role=body.role, email=body.email,
                 password_hash=security.hash_password(body.password), totp_secret="", recovery_codes=[],
                 enrolled=False, tenants=tenants)
        db.add(u)
        db.flush()
        grant = issue_enroll_code(u)
        audit.record(db, user.username, "user.create", "user", u.id, None,
                     {"role": body.role, "clients": [t.key for t in tenants], "activation": grant["activation"]})
        commit(db)
        return {**user_view(u), **grant}  # mot de passe temporaire : le titulaire le change à sa première connexion

    @app.patch("/api/v1/admin/users/{username}")
    def users_patch(username: str, body: UserPatchIn, user: User = Depends(current_user),
                    db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        u = get_user(db, username)
        sent = body.model_fields_set
        role = body.role if "role" in sent and body.role else u.role
        tenants = tenants_by_keys(db, body.clients) if "clients" in sent and body.clients is not None else list(u.tenants)
        check_role_clients(role, tenants)
        if u.id == user.id and (role != u.role or body.active is False):
            raise HTTPException(409, "Vous ne pouvez pas modifier votre propre rôle ni vous désactiver.")
        changes = {}
        if "display_name" in sent and body.display_name:
            u.display_name = body.display_name
        if "email" in sent:
            u.email = body.email
        if role != u.role:
            changes["role"] = [u.role, role]
            u.role = role
        if [t.key for t in tenants] != [t.key for t in u.tenants]:
            changes["clients"] = [t.key for t in tenants]
            u.tenants = tenants
        if "active" in sent and body.active is not None and body.active != u.active:
            changes["active"] = body.active
            u.active = body.active
        if changes.get("active") is False or "role" in changes or "clients" in changes:
            drop_sessions(db, u)  # les droits changent : reconnexion obligatoire
        audit.record(db, user.username, "user.update", "user", u.id, None, changes)
        commit(db)
        return user_view(u)

    @app.post("/api/v1/admin/users/{username}/reset-2fa")
    def users_reset_2fa(username: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Réinitialisation de la 2FA, réservée à l'Admin et tracée [plan : exigences fonctionnelles]."""
        require_role(user, "admin")
        u = get_user(db, username)
        require_enrollment(u)
        u.failed_attempts, u.locked_until = 0, None
        drop_sessions(db, u)
        grant = issue_enroll_code(u)
        audit.record(db, user.username, "user.reset_2fa", "user", u.id, None, {"activation": grant["activation"]})
        commit(db)
        return {**user_view(u), **grant}

    @app.post("/api/v1/admin/users/{username}/reset-password")
    def users_reset_password(username: str, body: PasswordResetIn, user: User = Depends(current_user),
                             db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        u = get_user(db, username)
        u.password_hash = security.hash_password(body.password)
        u.failed_attempts, u.locked_until = 0, None
        drop_sessions(db, u)
        grant = issue_enroll_code(u) if not u.enrolled else {}
        audit.record(db, user.username, "user.reset_password", "user", u.id, None, {"activation": grant["activation"]} if grant else {})
        commit(db)
        return {**user_view(u), **grant}

    # ---------------------------------------------------------------- clients
    def client_view(t: Tenant, tickets: int = 0) -> dict:
        return {"key": t.key, "name": t.name, "contact_emails": t.contact_emails or [],
                "severity_grid": t.severity_grid, "retention_months": t.retention_months, "sla": t.sla,
                "max_attachment_mb": t.max_attachment_mb,
                "tickets": tickets, "created_at": rfc3339(t.created_at)}

    @app.get("/api/v1/admin/clients")
    def clients_list(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        counts = dict(db.execute(select(Ticket.tenant_id, func.count()).group_by(Ticket.tenant_id)).all())
        return {"items": [client_view(t, counts.get(t.id, 0)) for t in db.scalars(select(Tenant).order_by(Tenant.key))]}

    @app.post("/api/v1/admin/clients", status_code=201)
    def clients_create(body: ClientCreateIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        key = body.key.upper()
        if db.scalars(select(Tenant).where(Tenant.key == key)).first():
            raise HTTPException(409, "Ce client existe déjà.")
        t = Tenant(key=key, name=body.name)
        db.add(t)
        db.flush()
        audit.record(db, user.username, "client.create", "tenant", key, t.id)
        commit(db)
        return client_view(t)

    @app.patch("/api/v1/admin/clients/{key}")
    def clients_patch(key: str, body: ClientPatchIn, user: User = Depends(current_user),
                      db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        t = db.scalars(select(Tenant).where(Tenant.key == key.upper()[:16])).first()
        if t is None:
            raise HTTPException(404, "Client introuvable.")
        sent = body.model_fields_set
        changed = []
        if "name" in sent and body.name:
            t.name = body.name
            changed.append("name")
        if "contact_emails" in sent:
            t.contact_emails = [e.strip() for e in (body.contact_emails or []) if "@" in e and len(e) <= 254]
            changed.append("contact_emails")
        if "severity_grid" in sent:
            if body.severity_grid is not None and not _grid_ok(body.severity_grid):
                raise HTTPException(422, "Grille invalide : 3 niveaux de dommages × 3 importances, gravités connues.")
            t.severity_grid = body.severity_grid
            changed.append("severity_grid")
        if "retention_months" in sent:
            t.retention_months = body.retention_months
            changed.append("retention_months")
        if "max_attachment_mb" in sent:
            t.max_attachment_mb = body.max_attachment_mb
            changed.append("max_attachment_mb")
        if "sla" in sent:
            if body.sla is not None and not _sla_ok(body.sla):
                raise HTTPException(422, "Délais invalides : par gravité, qualification et resolution en heures.")
            t.sla = body.sla
            changed.append("sla")
        audit.record(db, user.username, "client.update", "tenant", t.key, t.id, {"champs": changed})
        commit(db)
        return client_view(t)

    # ---------------------------------------------------------------- clés d'API
    def key_view(k: ApiKey, tenant: Tenant) -> dict:
        last = as_utc(k.last_used_at or k.created_at)  # clé neuve : le délai court depuis sa création
        silent = (not k.revoked) and (last is None or last < utcnow() - timedelta(hours=SILENT_KEY_HOURS))
        return {"id": k.id, "client": tenant.key, "name": k.name, "prefix": k.prefix, "revoked": k.revoked,
                "created_at": rfc3339(k.created_at), "last_used_at": rfc3339(k.last_used_at), "silent": silent}

    @app.get("/api/v1/admin/api-keys")
    def keys_list(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        rows = db.execute(select(ApiKey, Tenant).join(Tenant, Tenant.id == ApiKey.tenant_id)
                          .order_by(Tenant.key, ApiKey.created_at)).all()
        return {"items": [key_view(k, t) for k, t in rows], "silent_after_hours": SILENT_KEY_HOURS}

    @app.post("/api/v1/admin/api-keys", status_code=201)
    def keys_create(body: ApiKeyCreateIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        t = db.scalars(select(Tenant).where(Tenant.key == body.client.upper())).first()
        if t is None:
            raise HTTPException(422, "Client inconnu.")
        plain, prefix, digest = security.new_api_key()
        k = ApiKey(tenant_id=t.id, name=body.name, prefix=prefix, key_hash=digest)
        db.add(k)
        db.flush()
        audit.record(db, user.username, "apikey.create", "tenant", t.key, t.id, {"name": body.name, "prefix": prefix})
        commit(db)
        return {**key_view(k, t), "key": plain}  # clé en clair : affichée une seule fois

    @app.post("/api/v1/admin/api-keys/{key_id}/revoke")
    def keys_revoke(key_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        k = db.get(ApiKey, key_id[:36])
        if k is None:
            raise HTTPException(404, "Clé introuvable.")
        k.revoked = True
        t = db.get(Tenant, k.tenant_id)
        audit.record(db, user.username, "apikey.revoke", "tenant", t.key, t.id, {"prefix": k.prefix})
        commit(db)
        return key_view(k, t)

    @app.post("/api/v1/admin/api-keys/{key_id}/rotate", status_code=201)
    def keys_rotate(key_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Crée une clé de remplacement et révoque l'ancienne : à déployer sur le manager Wazuh aussitôt."""
        require_role(user, "admin")
        old = db.get(ApiKey, key_id[:36])
        if old is None:
            raise HTTPException(404, "Clé introuvable.")
        t = db.get(Tenant, old.tenant_id)
        plain, prefix, digest = security.new_api_key()
        new = ApiKey(tenant_id=t.id, name=old.name, prefix=prefix, key_hash=digest)
        db.add(new)
        old.revoked = True
        db.flush()
        audit.record(db, user.username, "apikey.rotate", "tenant", t.key, t.id,
                     {"old": old.prefix, "new": prefix})
        commit(db)
        return {**key_view(new, t), "key": plain}

    # ---------------------------------------------------------------- table MITRE
    @app.get("/api/v1/mitre/mappings")
    def mitre_list(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin", "manager")
        rows = db.scalars(select(MitreMapping).order_by(MitreMapping.technique_id)).all()
        return {"items": [{"id": m.id, "technique": m.technique_id, "name": m.technique_name, "tactic": m.tactic,
                           "rule_id": m.rule_id, "rule_group": m.rule_group, "created_by": m.created_by,
                           "created_at": rfc3339(m.created_at)} for m in rows]}

    @app.post("/api/v1/mitre/mappings", status_code=201)
    def mitre_create(body: MitreIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin", "manager")
        if not valid_technique(body.technique):
            raise HTTPException(422, "Identifiant MITRE invalide (ex. T1110 ou T1543.003).")
        if bool(body.rule_id) == bool(body.rule_group):
            raise HTTPException(422, "Indiquer soit un identifiant de règle, soit un groupe de règles.")
        m = MitreMapping(rule_id=body.rule_id, rule_group=body.rule_group, technique_id=body.technique,
                         technique_name=body.name, tactic=body.tactic, created_by=user.username)
        db.add(m)
        db.flush()
        audit.record(db, user.username, "mitre.mapping_create", None, body.technique, None,
                     {"rule": body.rule_id, "group": body.rule_group})
        commit(db)
        return {"id": m.id}

    @app.delete("/api/v1/mitre/mappings/{mapping_id}")
    def mitre_delete(mapping_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin", "manager")
        m = db.get(MitreMapping, mapping_id[:36])
        if m is None:
            raise HTTPException(404, "Correspondance introuvable.")
        db.delete(m)
        audit.record(db, user.username, "mitre.mapping_delete", None, m.technique_id, None,
                     {"rule": m.rule_id, "group": m.rule_group})
        commit(db)
        return {"status": "ok"}

    # ---------------------------------------------------------------- profil (chacun, son propre compte)
    @app.post("/api/v1/me/password")
    def change_password(body: ChangePasswordIn, request: Request, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        if not security.verify_password(user.password_hash, body.current):
            audit.record(db, user.username, "auth.password_change_failed", "user", user.id)
            commit(db)
            raise HTTPException(403, "Mot de passe actuel incorrect.")
        user.password_hash = security.hash_password(body.new)
        # Les autres sessions de ce compte sont fermées (la session courante est conservée).
        current = ctx.session_from_cookie(request, db)
        db.execute(delete(Session).where(Session.user_id == user.id,
                                         Session.token_hash != (current.token_hash if current else "")))
        audit.record(db, user.username, "auth.password_changed", "user", user.id)
        commit(db)
        return {"status": "ok"}

    @app.post("/api/v1/me/recovery-codes")
    def regen_codes(body: RegenCodesIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        if not security.verify_password(user.password_hash, body.password):
            raise HTTPException(403, "Mot de passe incorrect.")
        plain, hashed = security.new_recovery_codes()
        user.recovery_codes = hashed
        audit.record(db, user.username, "auth.recovery_codes_regenerated", "user", user.id)
        commit(db)
        return {"recovery_codes": plain}

    @app.get("/api/v1/me/sessions")
    def my_sessions(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        rows = db.scalars(select(Session).where(Session.user_id == user.id, Session.stage == "full")
                          .order_by(Session.created_at.desc())).all()
        return {"items": [{"id": s.token_hash[:16], "created_at": rfc3339(s.created_at),
                           "last_seen_at": rfc3339(s.last_seen_at)} for s in rows]}

    @app.delete("/api/v1/me/sessions/{session_id}")
    def revoke_session(session_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        rows = db.scalars(select(Session).where(Session.user_id == user.id,
                                                Session.token_hash.like(session_id[:16] + "%"))).all()
        if not rows:
            raise HTTPException(404, "Session introuvable.")
        for s in rows:
            db.delete(s)
        audit.record(db, user.username, "auth.session_revoked", "user", user.id)
        commit(db)
        return {"status": "ok"}

    # ---------------------------------------------------------------- état du système
    def _clamav_state() -> str:
        if not settings.clamav_host:
            return "non configuré"
        try:
            with socket.create_connection((settings.clamav_host, settings.clamav_port), timeout=2) as s:
                s.sendall(b"zPING\0")
                return "disponible" if s.recv(16).startswith(b"PONG") else "réponse inattendue"
        except OSError:
            return "injoignable"

    @app.get("/api/v1/admin/system")
    def system_status(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        os.makedirs(settings.attachments_dir, exist_ok=True)
        usage = shutil.disk_usage(settings.attachments_dir)
        since = utcnow() - timedelta(hours=24)
        failed = db.scalar(select(func.count()).select_from(Notification)
                           .where(Notification.status == "echec", Notification.ts >= since)) or 0
        silent = [k for k, t in db.execute(select(ApiKey, Tenant).join(Tenant, Tenant.id == ApiKey.tenant_id)).all()
                  if key_view(k, t)["silent"]]
        return {
            "generated_at": rfc3339(utcnow()),
            "database": "ok" if db.scalar(select(1)) == 1 else "erreur",
            "smtp": "configuré" if settings.smtp_host else "non configuré",
            "clamav": _clamav_state(),
            "syslog": "configuré" if settings.syslog_host else "non configuré",
            "disk_free_mb": usage.free // (1024 * 1024), "disk_total_mb": usage.total // (1024 * 1024),
            "notifications_failed_24h": failed,
            "silent_sources": len(silent),
        }
