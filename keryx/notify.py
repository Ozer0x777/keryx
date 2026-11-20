"""Notifications e-mail : uniquement la référence du ticket et un lien.

[PDIS IV.2.3.g] aucune information sur l'incident dans la notification ;
[PDIS IV.2.3.h, j] chaque notification est enregistrée (date, canal, destinataire, contenu, statut) ;
[RFC 8314 / RFC 3207] SMTP chiffré (TLS implicite ou STARTTLS), certificat vérifié.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import audit
from .config import Settings
from .ids import utcnow
from .models import Notification, Tenant, Ticket


def message_for(settings: Settings, ticket: Ticket) -> tuple[str, str]:
    subject = f"[Keryx] Nouveau ticket {ticket.ref}"
    body = (
        f"Un ticket a été ouvert : {ticket.ref}\n"
        f"Consultation (authentification requise) : {settings.public_url}/tickets/{ticket.ref}\n"
    )
    return subject, body


def queue_new_ticket(db: DbSession, settings: Settings, tenant: Tenant, ticket: Ticket) -> list[Notification]:
    """Enregistre une notification « en_attente » par contact du client (envoi après validation de la transaction)."""
    subject, body = message_for(settings, ticket)
    recipients = [e for e in (tenant.contact_emails or []) if isinstance(e, str) and "@" in e]
    out = []
    if not recipients:
        n = Notification(tenant_id=tenant.id, ticket_id=ticket.id, channel="email", recipient="(aucun contact)",
                         content=f"{subject}\n{body}", status="sans_destinataire")
        db.add(n)
        out.append(n)
    for r in recipients:
        n = Notification(tenant_id=tenant.id, ticket_id=ticket.id, channel="email", recipient=r,
                         content=f"{subject}\n{body}", status="en_attente")
        db.add(n)
        out.append(n)
    return out


def _send(settings: Settings, recipient: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if settings.smtp_tls == "ssl":
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_s, context=ctx)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_s)
        server.starttls(context=ctx)
    try:
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password or "")
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


def send_pending(session_factory, settings: Settings, notification_ids: list[str]) -> None:
    """Envoie les notifications en attente et met à jour le registre. Appelé hors transaction de requête."""
    if not notification_ids:
        return
    db = session_factory()
    try:
        rows = db.scalars(select(Notification).where(Notification.id.in_(notification_ids),
                                                     Notification.status == "en_attente")).all()
        for n in rows:
            subject, _, body = n.content.partition("\n")
            if not settings.smtp_host:
                n.status = "non_envoye_smtp_absent"
            else:
                try:
                    _send(settings, n.recipient, subject, body)
                    n.status = "envoye"
                except (OSError, smtplib.SMTPException) as exc:
                    n.status = "echec"
                    audit.record(db, "keryx", "notification.failed", "notification", n.id, n.tenant_id,
                                 {"error": type(exc).__name__})
            n.ts = utcnow()
            audit.record(db, "keryx", "notification.send", "notification", n.id, n.tenant_id,
                         {"status": n.status, "recipient": n.recipient})
        db.commit()
    finally:
        db.close()
