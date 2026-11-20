"""Conformité avancée : mode crise, visionneuse d'audit, référentiel MITRE (STIX), rétention.

[PRIS VI.5.5.1 registre de crise ; PDIS IV.3.9.c journalisation, IV.2.2.w rétention ; ISO/IEC 27002 8.15 ;
MITRE ATT&CK STIX 2.1.] L'Admin consulte le journal mais ne voit jamais le contenu des tickets : les détails des
entrées qui touchent à un ticket, une pièce, un rapport ou un modèle lui sont masqués.
"""
from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone

from fastapi import Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import false, func, select
from sqlalchemy.orm import Session as DbSession

from . import audit, mitre_stix, retention
from .ids import rfc3339, utcnow
from .models import CRISIS_KINDS, AuditEntry, CrisisEntry, MitreMapping, MitreTechnique, Tenant, Ticket, User

MAX_STIX_BYTES = 80 * 1024 * 1024
CONTENT_ACTIONS = ("ticket.", "attachment.", "report.", "registry.", "template.")


class CrisisToggleIn(BaseModel):
    active: bool
    reason: str = Field(min_length=3, max_length=500)


class CrisisEntryIn(BaseModel):
    kind: str
    body: str = Field(min_length=1, max_length=5000)
    owner: str | None = Field(default=None, max_length=120)
    due_at: datetime | None = None


class CrisisPatchIn(BaseModel):
    done: bool


class RetentionIn(BaseModel):
    dry_run: bool = True


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit
    load_ticket, event, settings = ctx.load_ticket, ctx.event, ctx.settings

    def staff(user: User) -> None:
        require_role(user, "analyst", "manager")

    # ---------------------------------------------------------------- mode crise
    def entry_view(e: CrisisEntry) -> dict:
        return {"id": e.id, "kind": e.kind, "body": e.body, "owner": e.owner, "due_at": rfc3339(e.due_at),
                "done": e.done, "created_by": e.created_by, "created_at": rfc3339(e.created_at)}

    def crisis_view(db: DbSession, t: Ticket) -> dict:
        rows = db.scalars(select(CrisisEntry).where(CrisisEntry.ticket_id == t.id).order_by(CrisisEntry.created_at)).all()
        return {"active": t.crisis, "started_at": rfc3339(t.crisis_started_at), "items": [entry_view(e) for e in rows]}

    @app.get("/api/v1/tickets/{ref}/crisis")
    def crisis_get(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        return crisis_view(db, load_ticket(db, user, ref))

    @app.post("/api/v1/tickets/{ref}/crisis")
    def crisis_toggle(ref: str, body: CrisisToggleIn, user: User = Depends(current_user),
                      db: DbSession = Depends(get_db)):
        """Ouverture par un analyste ou un manager ; clôture de la crise par un manager seulement."""
        staff(user)
        t = load_ticket(db, user, ref)
        if body.active == t.crisis:
            raise HTTPException(409, "La crise est déjà dans cet état.")
        if body.active:
            ctx.require_open(t)
            t.crisis, t.crisis_started_at = True, utcnow()
        else:
            require_role(user, "manager")
            t.crisis = False
        t.updated_at = utcnow()
        event(db, t, user, "crise_ouverte" if body.active else "crise_close", {"motif": body.reason})
        commit(db)
        return crisis_view(db, t)

    @app.post("/api/v1/tickets/{ref}/crisis/entries", status_code=201)
    def crisis_add(ref: str, body: CrisisEntryIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        t = load_ticket(db, user, ref)
        ctx.require_open(t)
        if not t.crisis:
            raise HTTPException(409, "Le mode crise n'est pas actif sur ce ticket.")
        if body.kind not in CRISIS_KINDS:
            raise HTTPException(422, f"Type attendu parmi : {', '.join(CRISIS_KINDS)}.")
        due = body.due_at.astimezone(timezone.utc) if body.due_at and body.due_at.tzinfo else body.due_at
        e = CrisisEntry(ticket_id=t.id, tenant_id=t.tenant_id, kind=body.kind, body=body.body.strip(),
                        owner=body.owner, due_at=due, created_by=user.username)
        db.add(e)
        db.flush()
        event(db, t, user, "crise_" + body.kind, {"id": e.id})
        commit(db)
        return crisis_view(db, t)

    @app.patch("/api/v1/tickets/{ref}/crisis/entries/{entry_id}")
    def crisis_patch(ref: str, entry_id: str, body: CrisisPatchIn, user: User = Depends(current_user),
                     db: DbSession = Depends(get_db)):
        staff(user)
        t = load_ticket(db, user, ref)
        ctx.require_open(t)
        e = db.get(CrisisEntry, entry_id[:36])
        if e is None or e.ticket_id != t.id:
            raise HTTPException(404, "Entrée introuvable.")
        if e.kind != "action":
            raise HTTPException(422, "Seules les actions du plan d'action se cochent.")
        e.done = body.done
        event(db, t, user, "crise_action_faite" if body.done else "crise_action_rouverte", {"id": e.id})
        commit(db)
        return crisis_view(db, t)

    # ---------------------------------------------------------------- visionneuse d'audit
    @app.get("/api/v1/audit/entries")
    def audit_entries(actor: str | None = Query(default=None, max_length=120),
                      action: str | None = Query(default=None, max_length=64),
                      object_id: str | None = Query(default=None, max_length=64),
                      client: str | None = Query(default=None, max_length=16),
                      start: date | None = Query(default=None, alias="from"), to: date | None = None,
                      before_seq: int | None = None, limit: int = 100,
                      user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Journal d'audit consultable : Admin (détails masqués pour tout ce qui touche au contenu) et Manager
        (entrées de ses clients uniquement)."""
        require_role(user, "admin", "manager")
        limit = max(1, min(limit, 200))
        q = select(AuditEntry).order_by(AuditEntry.seq.desc())
        tenants = {t.id: t for t in db.scalars(select(Tenant))}
        if user.role == "manager":
            q = q.where(AuditEntry.tenant_id.in_([t.id for t in user.tenants]))
        if client:
            tid = next((i for i, t in tenants.items() if t.key == client.upper()), None)
            q = q.where(AuditEntry.tenant_id == tid) if tid else q.where(false())
        if actor:
            q = q.where(AuditEntry.actor == actor)
        if action:
            q = q.where(AuditEntry.action.like(action.replace("%", "").replace("_", r"\_") + "%", escape="\\"))
        if object_id:
            q = q.where(AuditEntry.object_id == object_id)
        if start:
            q = q.where(AuditEntry.ts >= datetime.combine(start, time.min, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"))
        if to:
            q = q.where(AuditEntry.ts < datetime.combine(to + timedelta(days=1), time.min, tzinfo=timezone.utc)
                        .isoformat().replace("+00:00", "Z"))
        if before_seq:
            q = q.where(AuditEntry.seq < before_seq)
        rows = db.scalars(q.limit(limit + 1)).all()
        more = len(rows) > limit
        rows = rows[:limit]

        def view(e: AuditEntry) -> dict:
            masked = user.role == "admin" and e.action.startswith(CONTENT_ACTIONS)
            return {"seq": e.seq, "ts": e.ts, "actor": e.actor, "action": e.action, "object_type": e.object_type,
                    "object_id": e.object_id, "client": tenants[e.tenant_id].key if e.tenant_id in tenants else None,
                    "details": {"masque": True} if masked else e.details}

        out = {"items": [view(e) for e in rows], "next_before_seq": rows[-1].seq if more and rows else None}
        audit.record(db, user.username, "audit.view", None, None, None, {"count": len(rows)})
        commit(db)
        return out

    @app.get("/api/v1/audit/checkpoint")
    def audit_checkpoint(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Point de contrôle à archiver hors de Keryx : détecte la suppression des dernières entrées."""
        require_role(user, "admin")
        seq, seal = audit.head(db)
        audit.record(db, user.username, "audit.checkpoint", None, None, None, {"seq": seq})
        commit(db)
        return {"seq": seq, "seal": seal, "generated_at": rfc3339(utcnow()), "value": f"{seq}:{seal}"}

    # ---------------------------------------------------------------- référentiel MITRE (STIX 2.1)
    @app.post("/api/v1/mitre/import")
    def mitre_import(file: UploadFile = File(...), user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin", "manager")
        data = file.file.read(MAX_STIX_BYTES + 1)
        if len(data) > MAX_STIX_BYTES:
            raise HTTPException(413, "Fichier STIX trop volumineux (80 Mo maximum).")
        try:
            added, updated = mitre_stix.import_bundle(db, json.loads(data))
        except (ValueError, RecursionError) as exc:
            db.rollback()
            raise HTTPException(422, str(exc))
        audit.record(db, user.username, "mitre.import", None, None, None, {"ajoutees": added, "mises_a_jour": updated})
        commit(db)
        return {"added": added, "updated": updated,
                "total": db.scalar(select(func.count()).select_from(MitreTechnique))}

    @app.get("/api/v1/mitre/techniques")
    def mitre_techniques(q: str = Query(default="", max_length=60), user: User = Depends(current_user),
                         db: DbSession = Depends(get_db)):
        staff_or_admin = user.role in ("admin", "manager", "analyst")
        if not staff_or_admin:
            raise HTTPException(403, "Action non autorisée pour ce rôle.")
        like = "%" + q.strip().replace("%", "").replace("_", r"\_") + "%"
        rows = db.scalars(select(MitreTechnique).where(MitreTechnique.technique_id.ilike(like, escape="\\")
                                                       | MitreTechnique.name.ilike(like, escape="\\"))
                          .order_by(MitreTechnique.technique_id).limit(50)).all()
        return {"items": [{"id": r.technique_id, "name": r.name, "tactics": r.tactics} for r in rows]}

    @app.get("/api/v1/mitre/suggestions")
    def mitre_suggestions(min_count: int = Query(default=3, ge=2, le=50), user: User = Depends(current_user),
                          db: DbSession = Depends(get_db)):
        """Corrections manuelles répétées : la même technique ajoutée à la main sur des tickets de la même règle est
        proposée comme nouvelle entrée de la table de correspondance (plan : enrichissement MITRE, niveau 3)."""
        require_role(user, "admin", "manager")
        tenant_ids = None if user.role == "admin" else [t.id for t in user.tenants]
        q = select(Ticket.rule_id, Ticket.rule_description, Ticket.mitre).where(Ticket.mitre_source == "manuel")
        if tenant_ids is not None:
            q = q.where(Ticket.tenant_id.in_(tenant_ids))
        counts: dict[tuple[str, str], int] = {}
        label: dict[str, str] = {}
        for rule_id, desc, mitre in db.execute(q.limit(20000)).all():
            label.setdefault(rule_id, desc)
            for m in mitre or []:
                counts[(rule_id, m["id"])] = counts.get((rule_id, m["id"]), 0) + 1
        mapped = {(m.rule_id, m.technique_id) for m in db.scalars(select(MitreMapping).where(MitreMapping.rule_id.is_not(None)))}
        names = {r.technique_id: r for r in db.scalars(select(MitreTechnique))}
        items = [{"rule_id": r, "rule_description": label[r], "technique": t, "count": n,
                  "name": names[t].name if t in names else "", "tactics": names[t].tactics if t in names else []}
                 for (r, t), n in sorted(counts.items(), key=lambda kv: -kv[1]) if n >= min_count and (r, t) not in mapped]
        return {"items": items[:50], "min_count": min_count}

    # ---------------------------------------------------------------- rétention
    @app.post("/api/v1/admin/retention")
    def retention_run(body: RetentionIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        report = retention.run(db, settings, utcnow(), actor=user.username, dry_run=body.dry_run)
        if not body.dry_run:
            commit(db)
        return {"dry_run": body.dry_run, "items": report, "total": sum(r["alerts"] for r in report)}
