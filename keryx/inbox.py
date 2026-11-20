"""Notifications dans l'interface (cloche). Référence et nature de l'événement seulement, pas de détail."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .models import InboxItem, User


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
    db.add(InboxItem(user_id=user.id, kind=kind, ticket_ref=ticket_ref, actor=actor, dedup_key=dedup_key))
    return True
