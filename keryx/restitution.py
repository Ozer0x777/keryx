"""Réversibilité d'un client (PDIS IV.5.2.b et f) : restitution de toutes ses données, puis destruction complète.

Export : une archive ZIP avec, pour le client, ses tickets et tout leur contexte (registre des actions, commentaires,
alertes brutes, pièces et chaîne de possession, liens, registre de crise, actions demandées au client, recherches
d'empreintes), ses notifications, son parc d'agents Wazuh, ses modèles, ses horodatages et ses entrées du journal
d'audit, plus un manifeste qui donne l'empreinte SHA-256 de chaque fichier. Les secrets (identifiants des
connecteurs, clés d'API) ne sont jamais exportés.

Destruction : suppression de toutes les données du client, fichiers des pièces compris ; ses comptes Client sont
désactivés. Elle exige un export préalable inscrit au journal d'audit. Le journal d'audit, chaîné, est conservé : il
ne contient que des références (voir `docs/conformite/couverture-pdis.md`).
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import date, datetime

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as DbSession

from . import __version__, audit
from . import attachments as att
from .config import Settings
from .ids import rfc3339, utcnow
from .models import (
    ActionClient, ApiKey, Attachment, AuditEntry, Comment, CrisisEntry, CustodyEvent, HashLookup, InboxItem,
    Notification, RawAlert, Template, Tenant, Ticket, TicketEvent, TicketLink, Timestamp, User, UserTenant,
    WazuhAgent, WazuhAgentEvent,
)

_SECRET = ("password", "secret", "_enc", "token", "key_hash", "api_key", "_pem")


def _ser(v):
    if isinstance(v, datetime):
        return rfc3339(v)
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, bytes):
        return v.hex()
    return v


def _row(o) -> dict:
    return {c.key: _ser(getattr(o, c.key)) for c in o.__table__.columns if not any(s in c.key for s in _SECRET)}


def _rows(db: DbSession, model, *cond) -> list[dict]:
    return [_row(o) for o in db.scalars(select(model).where(*cond))]


def export_client(db: DbSession, settings: Settings, tenant: Tenant, out) -> dict:
    """Écrit l'archive du client dans `out` (fichier binaire). Renvoie les comptes par nature de donnée."""
    tickets = db.scalars(select(Ticket).where(Ticket.tenant_id == tenant.id).order_by(Ticket.seq)).all()
    ids = [t.id for t in tickets]
    pieces = db.scalars(select(Attachment).where(Attachment.tenant_id == tenant.id)).all()
    data = {
        "client.json": _row(tenant),
        "tickets.json": [_row(t) for t in tickets],
        "evenements.json": _rows(db, TicketEvent, TicketEvent.ticket_id.in_(ids)),
        "commentaires.json": _rows(db, Comment, Comment.ticket_id.in_(ids)),
        "alertes-brutes.json": _rows(db, RawAlert, RawAlert.tenant_id == tenant.id),
        "pieces.json": [_row(a) for a in pieces],
        "chaine-de-possession.json": _rows(db, CustodyEvent, CustodyEvent.attachment_id.in_([a.id for a in pieces])),
        "liens.json": _rows(db, TicketLink, TicketLink.tenant_id == tenant.id),
        "crise.json": _rows(db, CrisisEntry, CrisisEntry.tenant_id == tenant.id),
        "actions-client.json": _rows(db, ActionClient, ActionClient.tenant_id == tenant.id),
        "recherches-empreintes.json": _rows(db, HashLookup, HashLookup.tenant_id == tenant.id),
        "notifications.json": _rows(db, Notification, Notification.tenant_id == tenant.id),
        "parc-agents.json": _rows(db, WazuhAgent, WazuhAgent.tenant_id == tenant.id),
        "parc-evenements.json": _rows(db, WazuhAgentEvent, WazuhAgentEvent.tenant_id == tenant.id),
        "modeles.json": _rows(db, Template, Template.tenant_id == tenant.id),
        "horodatages.json": _rows(db, Timestamp, Timestamp.tenant_id == tenant.id),
        "journal-audit.json": _rows(db, AuditEntry, AuditEntry.tenant_id == tenant.id),
    }
    manifeste = {"client": tenant.key, "nom": tenant.name, "genere_le": rfc3339(utcnow()), "keryx": __version__,
                 "fichiers": {}, "comptes": {k: (len(v) if isinstance(v, list) else 1) for k, v in data.items()}}
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, content in data.items():
            raw = json.dumps(content, ensure_ascii=False, indent=1).encode("utf-8")
            z.writestr(name, raw)
            manifeste["fichiers"][name] = hashlib.sha256(raw).hexdigest()
        manquantes = []
        for a in pieces:
            if not a.storage_name:
                continue                                   # preuve externe : conservée hors de Keryx
            quarantaine = att.isole(a.scan_status)
            try:
                content = att.read(settings, a.storage_name, quarantaine)
            except (OSError, Exception):  # noqa: BLE001 - une pièce illisible est signalée, l'export continue
                manquantes.append(a.id)
                continue
            name = f"pieces/{a.id}-{att.safe_filename(a.filename)}" + (".quarantaine.zip" if quarantaine else "")
            z.writestr(name, content)
            manifeste["fichiers"][name] = hashlib.sha256(content).hexdigest()
        manifeste["pieces_illisibles"] = manquantes
        z.writestr("manifeste.json", json.dumps(manifeste, ensure_ascii=False, indent=1))
    return manifeste["comptes"] | {"pieces_illisibles": len(manquantes)}


def export_bytes(db: DbSession, settings: Settings, tenant: Tenant, actor: str) -> tuple[bytes, str]:
    buf = io.BytesIO()
    comptes = export_client(db, settings, tenant, buf)
    content = buf.getvalue()
    digest = hashlib.sha256(content).hexdigest()
    audit.record(db, actor, "client.export", "tenant", tenant.key, tenant.id,
                 {"sha256": digest, "octets": len(content), "tickets": comptes["tickets.json"]})
    return content, digest


def destroy_client(db: DbSession, settings: Settings, tenant: Tenant, actor: str, dry_run: bool = True,
                   sans_export: bool = False) -> dict:
    """Détruit toutes les données du client (PDIS IV.5.2.f). Simulation par défaut ; exige un export préalable."""
    exporte = db.scalars(select(AuditEntry).where(AuditEntry.action == "client.export",
                                                  AuditEntry.tenant_id == tenant.id)).first()
    if exporte is None and not sans_export:
        raise ValueError("Aucun export de ce client n'est inscrit au journal d'audit : exporter avant de détruire.")
    ids = list(db.scalars(select(Ticket.id).where(Ticket.tenant_id == tenant.id)))
    refs = list(db.scalars(select(Ticket.ref).where(Ticket.tenant_id == tenant.id)))
    pieces = db.scalars(select(Attachment).where(Attachment.tenant_id == tenant.id)).all()
    piece_ids = [a.id for a in pieces]
    plan = [
        ("chaine_de_possession", CustodyEvent, CustodyEvent.attachment_id.in_(piece_ids)),
        ("recherches_empreintes", HashLookup, HashLookup.tenant_id == tenant.id),
        ("pieces", Attachment, Attachment.tenant_id == tenant.id),
        ("alertes_brutes", RawAlert, RawAlert.tenant_id == tenant.id),
        ("commentaires", Comment, Comment.ticket_id.in_(ids)),
        ("evenements", TicketEvent, TicketEvent.ticket_id.in_(ids)),
        ("actions_client", ActionClient, ActionClient.tenant_id == tenant.id),
        ("liens", TicketLink, TicketLink.tenant_id == tenant.id),
        ("crise", CrisisEntry, CrisisEntry.tenant_id == tenant.id),
        ("notifications", Notification, Notification.tenant_id == tenant.id),
        ("boites_de_reception", InboxItem, InboxItem.ticket_ref.in_(refs)),
        ("horodatages", Timestamp, Timestamp.tenant_id == tenant.id),
        ("tickets", Ticket, Ticket.tenant_id == tenant.id),
        ("parc_evenements", WazuhAgentEvent, WazuhAgentEvent.tenant_id == tenant.id),
        ("parc_agents", WazuhAgent, WazuhAgent.tenant_id == tenant.id),
        ("modeles", Template, Template.tenant_id == tenant.id),
        ("cles_api", ApiKey, ApiKey.tenant_id == tenant.id),
    ]
    from sqlalchemy import func
    comptes = {nom: db.scalar(select(func.count()).select_from(model).where(cond)) or 0 for nom, model, cond in plan}
    clients = [u for u in db.scalars(select(User).join(UserTenant, UserTenant.user_id == User.id)
                                     .where(UserTenant.tenant_id == tenant.id, User.role == "client"))]
    comptes["comptes_client_desactives"] = len(clients)
    if dry_run:
        return comptes
    for a in pieces:
        if a.storage_name:
            for quarantaine in (False, True):
                try:
                    att.destroy(settings, a.storage_name, quarantaine)
                except Exception:  # noqa: BLE001 - fichier déjà absent : la destruction continue
                    pass
    for _, model, cond in plan:
        db.execute(delete(model).where(cond).execution_options(synchronize_session=False))
    for u in clients:
        u.active = False
    db.execute(delete(UserTenant).where(UserTenant.tenant_id == tenant.id))
    db.execute(update(Tenant).where(Tenant.id == tenant.id).values(
        astreinte_canal_id=None, escalade_canal_id=None, notif_secours_canal_id=None))
    key = tenant.key
    db.execute(delete(Tenant).where(Tenant.id == tenant.id))
    audit.record(db, actor, "client.destruction", "tenant", key, None, comptes)
    return comptes
