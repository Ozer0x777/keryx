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
from .models import TLP, Tenant, Ticket, TicketEvent, User, tlp_rang

OUVERTS = ("nouveau", "en_evaluation", "en_reponse")


class PolitiqueIn(BaseModel):
    """Seuls les champs envoyés changent."""
    tlp_plancher: str | None = Field(default=None, max_length=20)
    acquittement_rapport: bool | None = None


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit

    def vue(t: Tenant) -> dict:
        return {"key": t.key, "name": t.name, "tlp_plancher": t.tlp_plancher,
                "acquittement_rapport": bool(t.acquittement_rapport)}

    @app.get("/api/v1/politique")
    def politiques(user: User = Depends(current_user)):
        require_role(user, "manager")
        return {"items": [vue(t) for t in sorted(user.tenants, key=lambda t: t.key)], "tlp": list(TLP)}

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
                      "acquittement_rapport": bool(tenant.acquittement_rapport)})
        commit(db)
        return {**vue(tenant), "tickets_releves": releves}
