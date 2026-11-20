"""Confort de travail de l'analyste : liens entre tickets, fusion, modèles, notifications, filtres, affectation en masse.

[ISO/IEC 27035 : regrouper les incidents liés ; PDIS IV.2.1.e, r, s : échéances ; PDIS IV.2.3.g : une notification
ne contient jamais de détail de l'incident, ici seulement la référence et la nature de l'événement.]
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session as DbSession

from . import audit, sla
from .ids import rfc3339, utcnow
from .inbox import push
from .models import (INBOX_KINDS, LINK_KINDS, InboxItem, RawAlert, SavedFilter, Template, Tenant, Ticket, TicketLink,
                     User, Comment)
from .sanitize import clean_html


class LinkIn(BaseModel):
    ref: str = Field(max_length=32)
    kind: str


class MergeIn(BaseModel):
    into: str = Field(max_length=32)
    reason: str = Field(min_length=3, max_length=500)


class TemplateIn(BaseModel):
    kind: str
    name: str = Field(min_length=1, max_length=120)
    body_html: str = Field(max_length=50_000)
    client: str | None = Field(default=None, max_length=16)


class FilterIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    params: dict = Field(default_factory=dict)


class BulkAssignIn(BaseModel):
    refs: list[str] = Field(min_length=1, max_length=200)
    username: str | None = Field(default=None, max_length=120)


class ReadIn(BaseModel):
    ids: list[str] | None = Field(default=None, max_length=200)


class PrefsIn(BaseModel):
    prefs: dict[str, bool]


FILTER_KEYS = {"status", "client", "rex_en_attente", "q", "assignee", "overdue", "sort", "order"}


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit
    load_ticket, require_open, event = ctx.load_ticket, ctx.require_open, ctx.event

    def staff(user: User) -> None:
        require_role(user, "analyst", "manager")

    # ---------------------------------------------------------------- liens et fusion
    def link_views(db: DbSession, t: Ticket) -> list[dict]:
        rows = db.scalars(select(TicketLink).where((TicketLink.ticket_id == t.id) | (TicketLink.other_id == t.id))).all()
        out = []
        for ln in rows:
            outgoing = ln.ticket_id == t.id
            other = db.get(Ticket, ln.other_id if outgoing else ln.ticket_id)
            # Le parent vu de l'enfant s'appelle « parent » ; vu du parent, c'est un « enfant ».
            kind = ln.kind if outgoing or ln.kind != "parent" else "enfant"
            if ln.kind == "doublon" and not outgoing:
                kind = "doublon_de_celui-ci"
            out.append({"id": ln.id, "kind": kind, "ref": other.ref, "title": other.title, "status": other.status})
        return out

    @app.get("/api/v1/tickets/{ref}/links")
    def links_list(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        return {"items": link_views(db, load_ticket(db, user, ref))}

    @app.post("/api/v1/tickets/{ref}/links", status_code=201)
    def links_add(ref: str, body: LinkIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        t = load_ticket(db, user, ref)
        if body.kind not in LINK_KINDS:
            raise HTTPException(422, f"Type de lien attendu parmi : {', '.join(LINK_KINDS)}.")
        other = load_ticket(db, user, body.ref)  # cloisonnement : un ticket d'un autre client reste introuvable
        if other.id == t.id:
            raise HTTPException(422, "Un ticket ne peut pas être lié à lui-même.")
        if other.tenant_id != t.tenant_id:
            raise HTTPException(422, "Seuls des tickets du même client peuvent être liés.")
        dup = db.scalars(select(TicketLink).where(
            ((TicketLink.ticket_id == t.id) & (TicketLink.other_id == other.id))
            | ((TicketLink.ticket_id == other.id) & (TicketLink.other_id == t.id)))).first()
        if dup:
            raise HTTPException(409, "Ces tickets sont déjà liés.")
        db.add(TicketLink(tenant_id=t.tenant_id, ticket_id=t.id, other_id=other.id, kind=body.kind,
                          created_by=user.username))
        event(db, t, user, "lien", {"avec": other.ref, "type": body.kind})
        commit(db)
        return {"items": link_views(db, t)}

    @app.delete("/api/v1/tickets/{ref}/links/{link_id}")
    def links_delete(ref: str, link_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        t = load_ticket(db, user, ref)
        ln = db.get(TicketLink, link_id[:36])
        if ln is None or t.id not in (ln.ticket_id, ln.other_id):
            raise HTTPException(404, "Lien introuvable.")
        db.delete(ln)
        event(db, t, user, "lien_supprime", {"type": ln.kind})
        commit(db)
        return {"items": link_views(db, t)}

    @app.post("/api/v1/tickets/{ref}/merge")
    def merge(ref: str, body: MergeIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Fusion manuelle : ce ticket est un doublon de l'autre. Les alertes brutes et les commentaires sont
        rattachés au ticket conservé, ce ticket est clos en faux positif avec un lien « doublon »."""
        staff(user)
        src = load_ticket(db, user, ref)
        dst = load_ticket(db, user, body.into)
        require_open(src)
        require_open(dst)
        if src.id == dst.id or src.tenant_id != dst.tenant_id:
            raise HTTPException(422, "Fusion impossible : deux tickets distincts du même client sont nécessaires.")
        moved = db.execute(update(RawAlert).where(RawAlert.ticket_id == src.id).values(ticket_id=dst.id)).rowcount
        db.execute(update(Comment).where(Comment.ticket_id == src.id).values(ticket_id=dst.id))
        dst.occurrences += src.occurrences
        dst.updated_at = utcnow()
        src.verdict, src.status, src.updated_at = "faux_positif", "faux_positif", utcnow()
        src.closed_at = src.qualified_at = src.updated_at
        db.add(TicketLink(tenant_id=src.tenant_id, ticket_id=src.id, other_id=dst.id, kind="doublon",
                          created_by=user.username))
        event(db, src, user, "fusion", {"vers": dst.ref, "motif": body.reason, "alertes_deplacees": moved},
              visible_client=True)
        event(db, dst, user, "fusion_recue", {"depuis": src.ref, "alertes": moved})
        commit(db)
        return {"ref": src.ref, "merged_into": dst.ref, "occurrences": dst.occurrences}

    # ---------------------------------------------------------------- affectation en masse
    @app.post("/api/v1/tickets/bulk-assign")
    def bulk_assign(body: BulkAssignIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        target = None
        if body.username:
            target = db.scalars(select(User).where(User.username == body.username)).first()
            if target is None or not target.active or target.role not in ("analyst", "manager"):
                raise HTTPException(422, "Utilisateur inconnu ou inactif.")
        results = []
        for r in dict.fromkeys(body.refs):
            try:
                t = load_ticket(db, user, r)
                require_open(t)
                if target is not None and t.tenant_id not in [x.id for x in target.tenants]:
                    raise HTTPException(422, "Utilisateur non affecté à ce client.")
                ctx.assign_ticket(db, user, t, target)
                results.append({"ref": t.ref, "ok": True})
            except HTTPException as exc:
                results.append({"ref": r[:32], "ok": False, "error": str(exc.detail)})
        commit(db)
        return {"results": results, "done": sum(1 for x in results if x["ok"])}

    # ---------------------------------------------------------------- modèles
    @app.get("/api/v1/templates")
    def templates_list(kind: str | None = None, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        ids = [t.id for t in user.tenants]
        q = select(Template).where((Template.tenant_id.is_(None)) | (Template.tenant_id.in_(ids))).order_by(Template.name)
        if kind:
            q = q.where(Template.kind == kind)
        tenants = {t.id: t.key for t in user.tenants}
        return {"items": [{"id": m.id, "kind": m.kind, "name": m.name, "body_html": m.body_html,
                           "client": tenants.get(m.tenant_id)} for m in db.scalars(q)]}

    @app.post("/api/v1/templates", status_code=201)
    def templates_create(body: TemplateIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        if body.kind not in ("commentaire", "synthese"):
            raise HTTPException(422, "Type attendu : commentaire ou synthese.")
        tenant_id = None
        if body.client:
            tenant = next((t for t in user.tenants if t.key == body.client.upper()), None)
            if tenant is None:
                raise HTTPException(422, "Client inconnu ou non affecté.")
            tenant_id = tenant.id
        elif user.role != "manager":
            raise HTTPException(403, "Seul un manager crée un modèle commun à tous les clients.")
        m = Template(tenant_id=tenant_id, kind=body.kind, name=body.name, body_html=clean_html(body.body_html),
                     created_by=user.username)
        db.add(m)
        db.flush()
        audit.record(db, user.username, "template.create", "template", m.id, tenant_id, {"name": body.name})
        commit(db)
        return {"id": m.id}

    @app.delete("/api/v1/templates/{template_id}")
    def templates_delete(template_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        staff(user)
        m = db.get(Template, template_id[:36])
        visible = m and (m.tenant_id is None or m.tenant_id in [t.id for t in user.tenants])
        if not visible:
            raise HTTPException(404, "Modèle introuvable.")
        if user.role != "manager" and m.created_by != user.username:
            raise HTTPException(403, "Seul son auteur ou un manager supprime ce modèle.")
        db.delete(m)
        audit.record(db, user.username, "template.delete", "template", m.id, m.tenant_id)
        commit(db)
        return {"status": "ok"}

    # ---------------------------------------------------------------- notifications dans l'interface
    def refresh_deadlines(db: DbSession, user: User) -> None:
        """Dépose une alerte d'échéance, une seule fois par échéance, pour les tickets qu'on vous a affectés."""
        if user.role not in ("analyst", "manager"):
            return
        tenants = {t.id: t for t in user.tenants}
        rows = db.scalars(select(Ticket).where(Ticket.assignee_id == user.id,
                                               Ticket.status.in_(("nouveau", "en_evaluation", "en_reponse"))).limit(300))
        for t in rows:
            s = sla.state(t, tenants.get(t.tenant_id))
            if s["overdue"]:
                push(db, user, "echeance", t.ref, dedup_key=f"echeance:{t.ref}:{s['due_resolution'] or s['due_qualification']}")

    @app.get("/api/v1/notifications")
    def inbox_list(limit: int = 30, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        refresh_deadlines(db, user)
        db.commit()
        limit = max(1, min(limit, 100))
        rows = db.scalars(select(InboxItem).where(InboxItem.user_id == user.id)
                          .order_by(InboxItem.ts.desc()).limit(limit)).all()
        unread = db.scalar(select(func.count()).select_from(InboxItem)
                           .where(InboxItem.user_id == user.id, InboxItem.read_at.is_(None))) or 0
        return {"unread": unread, "items": [{"id": n.id, "kind": n.kind, "ref": n.ticket_ref, "actor": n.actor,
                                             "ts": rfc3339(n.ts), "read": n.read_at is not None} for n in rows]}

    @app.get("/api/v1/notifications/count")
    def inbox_count(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        return {"unread": db.scalar(select(func.count()).select_from(InboxItem)
                                    .where(InboxItem.user_id == user.id, InboxItem.read_at.is_(None))) or 0}

    @app.post("/api/v1/notifications/read")
    def inbox_read(body: ReadIn | None = None, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        q = update(InboxItem).where(InboxItem.user_id == user.id, InboxItem.read_at.is_(None))
        if body and body.ids:
            q = q.where(InboxItem.id.in_([i[:36] for i in body.ids[:200]]))
        db.execute(q.values(read_at=utcnow()))
        db.commit()
        return {"status": "ok"}

    @app.get("/api/v1/me/preferences")
    def prefs_get(user: User = Depends(current_user)):
        return {"kinds": list(INBOX_KINDS), "prefs": {k: (user.notif_prefs or {}).get(k, True) for k in INBOX_KINDS}}

    @app.put("/api/v1/me/preferences")
    def prefs_put(body: PrefsIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        if any(k not in INBOX_KINDS for k in body.prefs):
            raise HTTPException(422, f"Types attendus parmi : {', '.join(INBOX_KINDS)}.")
        user.notif_prefs = {k: bool(v) for k, v in body.prefs.items()}
        db.commit()
        return {"prefs": user.notif_prefs}

    # ---------------------------------------------------------------- filtres enregistrés
    @app.get("/api/v1/me/filters")
    def filters_list(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        rows = db.scalars(select(SavedFilter).where(SavedFilter.user_id == user.id).order_by(SavedFilter.name)).all()
        return {"items": [{"id": f.id, "name": f.name, "params": f.params} for f in rows]}

    @app.post("/api/v1/me/filters", status_code=201)
    def filters_create(body: FilterIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        params = {k: v for k, v in body.params.items() if k in FILTER_KEYS and isinstance(v, (str, bool, int))}
        count = db.scalar(select(func.count()).select_from(SavedFilter).where(SavedFilter.user_id == user.id)) or 0
        if count >= 30:
            raise HTTPException(409, "30 filtres enregistrés au maximum.")
        f = SavedFilter(user_id=user.id, name=body.name, params=params)
        db.add(f)
        db.commit()
        return {"id": f.id, "name": f.name, "params": f.params}

    @app.delete("/api/v1/me/filters/{filter_id}")
    def filters_delete(filter_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        res = db.execute(delete(SavedFilter).where(SavedFilter.id == filter_id[:36], SavedFilter.user_id == user.id))
        db.commit()
        if not res.rowcount:
            raise HTTPException(404, "Filtre introuvable.")
        return {"status": "ok"}
