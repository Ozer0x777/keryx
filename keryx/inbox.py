"""Notifications dans l'interface (cloche). Référence et nature de l'événement seulement, pas de détail."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from .models import InboxItem, Ticket, User


def push(db: DbSession, user: User, kind: str, ticket_ref: str, actor: str | None = None,
         dedup_key: str | None = None) -> bool:
    """Dépose une notification si l'utilisateur ne l'a pas désactivée et si elle n'existe pas déjà."""
    if user is None or not user.active:
        return False
    if (user.notif_prefs or {}).get(kind) is False:
        return False
    if dedup_key and db.scalars(select(InboxItem.id).where(InboxItem.user_id == user.id,
                                                           InboxItem.dedup_key == dedup_key)).first():
        return False
    try:
        with db.begin_nested():
            db.add(InboxItem(user_id=user.id, kind=kind, ticket_ref=ticket_ref, actor=actor, dedup_key=dedup_key))
            db.flush()
    except IntegrityError:
        return False  # déposée entre-temps par une requête concurrente
    return True


def prevenir_clients(db: DbSession, t: Ticket, kind: str, actor: str | None = None) -> None:
    """Prévient les comptes Client actifs du client du ticket (cloche), selon leurs préférences."""
    for u in db.scalars(select(User).where(User.role == "client", User.active.is_(True))).all():
        if t.tenant_id in [x.id for x in u.tenants]:
            push(db, u, kind, t.ref, actor=actor)
