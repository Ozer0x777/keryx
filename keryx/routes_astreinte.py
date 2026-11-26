"""Canaux d'astreinte (ADR-0032), déclarés par l'Admin : une adresse appelée par le serveur est un réglage de sécurité,
comme les connecteurs Wazuh et VirusTotal. L'Admin ne lit aucun ticket ; le manager choisit ensuite, pour chacun de
ses clients, le canal d'astreinte et le canal d'escalade parmi ceux-ci (keryx/routes_politique.py).

L'adresse complète et le secret ne sont jamais renvoyés : seul un libellé (hôte du webhook, adresse courriel) l'est.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import astreinte, audit
from .ids import rfc3339, utcnow
from .models import OnCallChannel, User


class CanalIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: str
    target: str = Field(min_length=3, max_length=1000)
    secret: str | None = Field(default=None, max_length=200)
    include_title: bool = False


class CanalPatch(BaseModel):
    """Seuls les champs envoyés changent ; « secret » vide retire la signature."""
    name: str | None = Field(default=None, min_length=2, max_length=80)
    target: str | None = Field(default=None, min_length=3, max_length=1000)
    secret: str | None = Field(default=None, max_length=200)
    include_title: bool | None = None
    active: bool | None = None


def vue(c: OnCallChannel) -> dict:
    return {"id": c.id, "name": c.name, "kind": c.kind, "target": c.target_label, "signed": bool(c.secret_enc),
            "include_title": bool(c.include_title), "active": bool(c.active), "created_at": rfc3339(c.created_at)}


def register(app, ctx) -> None:
    get_db, current_user, commit, box, settings = ctx.get_db, ctx.current_user, ctx.commit, ctx.box, ctx.settings
    guard = [Depends(ctx.admin_guard)]

    def checked(kind: str, target: str) -> str:
        try:
            return astreinte.check_target(kind, target)
        except astreinte.ChannelError as exc:
            raise HTTPException(422, str(exc)) from None

    def unique(db: DbSession, name: str, other: str | None = None) -> str:
        name = name.strip()
        found = db.scalars(select(OnCallChannel).where(OnCallChannel.name == name)).first()
        if found is not None and found.id != other:
            raise HTTPException(409, "Un canal porte déjà ce nom.")
        return name

    @app.get("/api/v1/admin/canaux", dependencies=guard)
    def canaux(db: DbSession = Depends(get_db)):
        rows = db.scalars(select(OnCallChannel).order_by(OnCallChannel.name)).all()
        return {"items": [vue(c) for c in rows], "kinds": list(astreinte.KINDS)}

    @app.post("/api/v1/admin/canaux", status_code=201, dependencies=guard)
    def creer(body: CanalIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        label = checked(body.kind, body.target)
        if body.secret and body.kind != "webhook_json":
            raise HTTPException(422, "La signature ne s'applique qu'au webhook JSON générique.")
        c = OnCallChannel(name=unique(db, body.name), kind=body.kind, target_label=label, target_enc="",
                          include_title=body.include_title, created_at=utcnow())
        db.add(c)
        db.flush()
        c.target_enc = box.encrypt(body.target.strip(), f"canal:{c.id}")
        if body.secret:
            c.secret_enc = box.encrypt(body.secret, f"canal-secret:{c.id}")
        audit.record(db, user.username, "astreinte.canal_cree", "canal", c.name, None,
                     {"type": c.kind, "cible": label, "signe": bool(c.secret_enc), "titre": c.include_title})
        commit(db)
        return vue(c)

    @app.put("/api/v1/admin/canaux/{canal_id}", dependencies=guard)
    def modifier(canal_id: str, body: CanalPatch, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        c = db.get(OnCallChannel, canal_id)
        if c is None:
            raise HTTPException(404, "Canal inconnu.")
        sent = body.model_fields_set
        changes = []
        if body.name is not None:
            c.name = unique(db, body.name, c.id)
            changes.append("nom")
        if body.target is not None:
            c.target_label = checked(c.kind, body.target)
            c.target_enc = box.encrypt(body.target.strip(), f"canal:{c.id}")
            changes.append("adresse")
        if "secret" in sent:
            if body.secret and c.kind != "webhook_json":
                raise HTTPException(422, "La signature ne s'applique qu'au webhook JSON générique.")
            c.secret_enc = box.encrypt(body.secret, f"canal-secret:{c.id}") if body.secret else None
            changes.append("secret")
        if body.include_title is not None:
            c.include_title = body.include_title
            changes.append("titre")
        if body.active is not None:
            c.active = body.active
            changes.append("actif" if body.active else "inactif")
        audit.record(db, user.username, "astreinte.canal_modifie", "canal", c.name, None,
                     {"champs": changes, "cible": c.target_label})
        commit(db)
        return vue(c)

    @app.post("/api/v1/admin/canaux/{canal_id}/essai", dependencies=guard)
    def essai(canal_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Message d'essai, sans donnée de ticket : vérifie l'adresse, le certificat et la réponse du service."""
        c = db.get(OnCallChannel, canal_id)
        if c is None:
            raise HTTPException(404, "Canal inconnu.")
        text = f"[Keryx] Essai du canal « {c.name} » : message de test, aucune action demandée."
        msg = {"text": text, "data": {"type": "keryx.essai", "canal": c.name}}
        try:
            code = astreinte.deliver(settings, box, c, msg)
            out = {"statut": "envoye", "code": code}
        except astreinte.DeliveryError as exc:
            out = {"statut": "echec", "code": exc.http_status, "erreur": exc.reason}
        audit.record(db, user.username, "astreinte.canal_essai", "canal", c.name, None, out)
        commit(db)
        return out
