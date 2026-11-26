"""Politique du client (ADR-0033, ADR-0032), réglée par le manager pour les clients dont il a la charge : TLP plancher,
délai d'acquittement dans le rapport remis au client.

Les tickets et les pièces d'un client naissent à son TLP plancher ; un analyste ne peut pas descendre en dessous, un
manager le peut sur un ticket avec un motif tracé (keryx/api.py, qualification). Relever le plancher relève les tickets
ouverts qui sont en dessous ; le baisser ne baisse aucun ticket. Tout est inscrit au journal d'audit.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import audit
from .ids import utcnow
from .astreinte import CRITICITES, DELAIS_DEFAUT
from .models import TLP, OnCallChannel, Tenant, Ticket, TicketEvent, User, tlp_rang

OUVERTS = ("nouveau", "en_evaluation", "en_reponse")


class PolitiqueIn(BaseModel):
    """Seuls les champs envoyés changent."""
    tlp_plancher: str | None = Field(default=None, max_length=20)
    acquittement_rapport: bool | None = None
    # Astreinte (ADR-0032)
    astreinte_active: bool | None = None
    astreinte_criticites: list[str] | None = Field(default=None, max_length=4)
    astreinte_delais: dict[str, int] | None = None
    astreinte_canal_id: str | None = Field(default=None, max_length=36)
    escalade_canal_id: str | None = Field(default=None, max_length=36)


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit

    def vue(t: Tenant) -> dict:
        return {"key": t.key, "name": t.name, "tlp_plancher": t.tlp_plancher,
                "acquittement_rapport": bool(t.acquittement_rapport),
                "astreinte": {"active": bool(t.astreinte_active),
                              "criticites": list(t.astreinte_criticites or ["Critique"]),
                              "delais": {**DELAIS_DEFAUT, **(t.astreinte_delais or {})},
                              "canal_id": t.astreinte_canal_id, "escalade_canal_id": t.escalade_canal_id}}

    @app.get("/api/v1/politique")
    def politiques(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "manager")
        # Le manager voit le nom et le type des canaux actifs, jamais leur adresse.
        canaux = db.scalars(select(OnCallChannel).where(OnCallChannel.active.is_(True)).order_by(OnCallChannel.name)).all()
        return {"items": [vue(t) for t in sorted(user.tenants, key=lambda t: t.key)], "tlp": list(TLP),
                "criticites": list(CRITICITES), "canaux": [{"id": c.id, "name": c.name, "kind": c.kind} for c in canaux]}

    def canal(db: DbSession, canal_id: str | None) -> str | None:
        if not canal_id:
            return None
        c = db.get(OnCallChannel, canal_id)
        if c is None or not c.active:
            raise HTTPException(422, "Canal d'astreinte inconnu ou désactivé.")
        return c.id

    def regler_astreinte(db: DbSession, tenant: Tenant, body: PolitiqueIn) -> dict:
        sent = body.model_fields_set
        avant = {"active": bool(tenant.astreinte_active), "criticites": tenant.astreinte_criticites,
                 "delais": tenant.astreinte_delais, "canal": tenant.astreinte_canal_id, "escalade": tenant.escalade_canal_id}
        if "astreinte_criticites" in sent:
            crits = body.astreinte_criticites or []
            if any(c not in CRITICITES for c in crits):
                raise HTTPException(422, f"Criticités attendues parmi : {', '.join(CRITICITES)}.")
            tenant.astreinte_criticites = [c for c in CRITICITES if c in crits]
        if "astreinte_delais" in sent:
            delais = body.astreinte_delais or {}
            if any(k not in CRITICITES or not 1 <= int(v) <= 1440 for k, v in delais.items()):
                raise HTTPException(422, "Délai d'escalade attendu entre 1 et 1440 minutes, par criticité.")
            tenant.astreinte_delais = {**DELAIS_DEFAUT, **{k: int(v) for k, v in delais.items()}}
        if "astreinte_canal_id" in sent:
            tenant.astreinte_canal_id = canal(db, body.astreinte_canal_id)
        if "escalade_canal_id" in sent:
            tenant.escalade_canal_id = canal(db, body.escalade_canal_id)
        if body.astreinte_active is not None:
            tenant.astreinte_active = body.astreinte_active
        if tenant.astreinte_active:
            if not tenant.astreinte_canal_id:
                raise HTTPException(422, "Choisir le canal d'astreinte avant d'activer l'astreinte de ce client.")
            if not tenant.astreinte_criticites:
                tenant.astreinte_criticites = ["Critique"]
        apres = {"active": bool(tenant.astreinte_active), "criticites": tenant.astreinte_criticites,
                 "delais": tenant.astreinte_delais, "canal": tenant.astreinte_canal_id, "escalade": tenant.escalade_canal_id}
        return {"astreinte_avant": avant, "astreinte": apres} if avant != apres else {}

    @app.put("/api/v1/politique/{client}")
    def regler(client: str, body: PolitiqueIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "manager")
        tenant = next((t for t in user.tenants if t.key == client.upper()), None)
        if tenant is None:
            raise HTTPException(404, "Client inconnu.")       # même réponse qu'un client inexistant
        tenant = db.get(Tenant, tenant.id)
        sent = body.model_fields_set
        nouveau = (body.tlp_plancher or None) if "tlp_plancher" in sent else tenant.tlp_plancher
        if nouveau is not None and nouveau not in TLP:
            raise HTTPException(422, f"Marquage attendu parmi : {', '.join(TLP)}.")
        avant, rapport_avant = tenant.tlp_plancher, bool(tenant.acquittement_rapport)
        tenant.tlp_plancher = nouveau
        if body.acquittement_rapport is not None:
            tenant.acquittement_rapport = body.acquittement_rapport
        trace_astreinte = regler_astreinte(db, tenant, body)
        releves = []
        if tlp_rang(nouveau) > tlp_rang(avant):
            # Plancher relevé : les tickets ouverts en dessous montent (plus restrictif, sans risque), chacun tracé.
            now = utcnow()
            for t in db.scalars(select(Ticket).where(Ticket.tenant_id == tenant.id, Ticket.status.in_(OUVERTS))):
                if tlp_rang(t.tlp) < tlp_rang(nouveau):
                    db.add(TicketEvent(ticket_id=t.id, actor=user.username, action="tlp_releve",
                                       details={"de": t.tlp, "vers": nouveau, "plancher": nouveau}))
                    t.tlp, t.updated_at = nouveau, now
                    releves.append(t.ref)
        audit.record(db, user.username, "client.politique", "tenant", tenant.key, tenant.id,
                     {"tlp_plancher_avant": avant, "tlp_plancher": nouveau, "tickets_releves": len(releves),
                      "acquittement_rapport_avant": rapport_avant,
                      "acquittement_rapport": bool(tenant.acquittement_rapport), **trace_astreinte})
        commit(db)
        return {**vue(tenant), "tickets_releves": releves}
