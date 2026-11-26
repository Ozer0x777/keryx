"""Suivi d'un ticket par le client (PDIS IV.2.3.l, tel que la trame d'évaluation le vérifie : « le suivi et la
modification de l'état des tickets », « la visualisation des actions associées »).

Le client modifie l'état du ticket de son côté (pris en compte, en cours chez lui, traité de son côté) et peut
demander la clôture ou la réouverture ; l'équipe accepte en changeant le statut, ou refuse avec un motif. Il met à jour
l'état des actions que l'équipe lui demande. La qualification, la gravité et la clôture restent à l'équipe. Tout est
inscrit au registre des actions du ticket, visible du client.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import inbox
from .ids import rfc3339, utcnow
from .models import TERMINAL_STATUSES, ActionClient, Ticket, User

ETATS_CLIENT = ("pris_en_compte", "en_cours", "traite")
DEMANDES = ("cloture", "reouverture")
ETATS_ACTION = ("a_faire", "faite", "impossible")
MIN_MOTIF = 10


class EtatClientIn(BaseModel):
    etat: str | None = None
    demande: str | None = None
    commentaire: str | None = Field(default=None, max_length=2000)


class RefusIn(BaseModel):
    motif: str = Field(min_length=MIN_MOTIF, max_length=2000)


class ActionIn(BaseModel):
    libelle: str = Field(min_length=3, max_length=500)


class ActionMajIn(BaseModel):
    etat: str
    commentaire: str | None = Field(default=None, max_length=2000)


def vue_suivi(db: DbSession, t: Ticket) -> dict:
    actions = db.scalars(select(ActionClient).where(ActionClient.ticket_id == t.id).order_by(ActionClient.cree_le)).all()
    return {"suivi_client": {"etat": t.etat_client, "demande": t.demande_client, "maj_le": rfc3339(t.etat_client_at)},
            "actions_client": [{"id": a.id, "libelle": a.libelle, "etat": a.etat, "commentaire": a.commentaire,
                                "cree_par": a.cree_par, "cree_le": rfc3339(a.cree_le), "maj_par": a.maj_par,
                                "maj_le": rfc3339(a.maj_le)} for a in actions]}


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit
    load_ticket, event = ctx.load_ticket, ctx.event

    def prevenir_equipe(db: DbSession, t: Ticket, user: User) -> None:
        """L'assigné, sinon toute l'équipe du client (comme pour une réponse du client)."""
        assignee = db.get(User, t.assignee_id) if t.assignee_id else None
        cibles = [assignee] if assignee is not None and assignee.active else [
            u for u in db.scalars(select(User).where(User.role.in_(("analyst", "manager")), User.active.is_(True))).all()
            if t.tenant_id in [x.id for x in u.tenants]]
        for u in cibles:
            inbox.push(db, u, "reponse_client", t.ref, actor=user.username)

    @app.post("/api/v1/tickets/{ref}/etat-client")
    def etat_client(ref: str, body: EtatClientIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "client")
        t = load_ticket(db, user, ref)
        if body.etat is not None and body.etat not in ETATS_CLIENT:
            raise HTTPException(422, f"État attendu parmi : {', '.join(ETATS_CLIENT)}.")
        if body.demande is not None and body.demande not in DEMANDES:
            raise HTTPException(422, f"Demande attendue parmi : {', '.join(DEMANDES)}.")
        clos = t.status in TERMINAL_STATUSES
        if body.demande == "cloture" and clos:
            raise HTTPException(409, "Le ticket est déjà clos.")
        if body.demande == "reouverture" and not clos:
            raise HTTPException(409, "Le ticket est encore ouvert.")
        if body.etat is None and body.demande is None:
            raise HTTPException(422, "Indiquer un état ou une demande.")
        if body.etat is not None:
            t.etat_client = body.etat
        if body.demande is not None:
            t.demande_client = body.demande
        t.etat_client_at = t.updated_at = utcnow()
        details = {"etat": t.etat_client, "demande": body.demande}
        if body.commentaire and body.commentaire.strip():
            details["commentaire"] = body.commentaire.strip()
        event(db, t, user, "etat_client", details, visible_client=True)
        prevenir_equipe(db, t, user)
        commit(db)
        return vue_suivi(db, t)

    @app.post("/api/v1/tickets/{ref}/demande-client/refus")
    def refuser(ref: str, body: RefusIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        if not t.demande_client:
            raise HTTPException(409, "Aucune demande du client en attente.")
        event(db, t, user, "demande_client_refusee", {"demande": t.demande_client, "motif": body.motif.strip()},
              visible_client=True)
        t.demande_client, t.updated_at = None, utcnow()
        commit(db)
        return vue_suivi(db, t)

    @app.post("/api/v1/tickets/{ref}/actions-client", status_code=201)
    def ajouter_action(ref: str, body: ActionIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        ctx.require_open(t)
        a = ActionClient(ticket_id=t.id, tenant_id=t.tenant_id, libelle=body.libelle.strip(), cree_par=user.username,
                         cree_le=utcnow())
        db.add(a)
        db.flush()
        event(db, t, user, "action_client_demandee", {"id": a.id, "libelle": a.libelle}, visible_client=True)
        commit(db)
        return vue_suivi(db, t)

    @app.patch("/api/v1/tickets/{ref}/actions-client/{action_id}")
    def maj_action(ref: str, action_id: str, body: ActionMajIn, user: User = Depends(current_user),
                   db: DbSession = Depends(get_db)):
        require_role(user, "client")
        t = load_ticket(db, user, ref)
        a = db.get(ActionClient, action_id)
        if a is None or a.ticket_id != t.id:
            raise HTTPException(404, "Action inconnue.")
        if body.etat not in ETATS_ACTION:
            raise HTTPException(422, f"État attendu parmi : {', '.join(ETATS_ACTION)}.")
        a.etat, a.maj_par, a.maj_le = body.etat, user.username, utcnow()
        a.commentaire = (body.commentaire or "").strip() or a.commentaire
        event(db, t, user, "action_client_maj", {"id": a.id, "libelle": a.libelle, "etat": a.etat,
                                                 **({"commentaire": a.commentaire} if a.commentaire else {})},
              visible_client=True)
        prevenir_equipe(db, t, user)
        commit(db)
        return vue_suivi(db, t)
