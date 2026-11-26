"""Notifications e-mail : uniquement la référence du ticket et un lien.

[PDIS IV.2.3.g] aucune information sur l'incident dans la notification ;
[PDIS IV.2.3.h, j] chaque notification est enregistrée (date, canal, destinataire, contenu, statut) ;
[RFC 8314 / RFC 3207] SMTP chiffré (TLS implicite ou STARTTLS), certificat vérifié.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from . import audit
from .config import Settings
from .ids import as_utc, utcnow
from .models import Notification, Tenant, Ticket

CRITICITES = ("Faible", "Moyenne", "Élevée", "Critique")     # du moins au plus grave
ECHECS_NOMINAL = ("echec", "non_envoye_smtp_absent", "sans_destinataire")


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
    # Personnes à notifier selon la gravité (PDIS IV.2.3.d) : un contact peut ne recevoir qu'à partir d'une criticité.
    seuils = tenant.contacts_criticite or {}
    rang = CRITICITES.index(ticket.criticite_initiale) if ticket.criticite_initiale in CRITICITES else len(CRITICITES)
    recipients = [e for e in recipients if seuils.get(e) not in CRITICITES or CRITICITES.index(seuils[e]) <= rang]
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
    from .astreinte import send_pending as send_oncall
    send_oncall(session_factory, settings, notification_ids)     # astreinte de l'équipe d'abord (ADR-0032)
    db = session_factory()
    try:
        rows = db.scalars(select(Notification).where(Notification.id.in_(notification_ids),
                                                     Notification.status == "en_attente",
                                                     Notification.canal_id.is_(None))).all()
        for n in rows:
            subject, _, body = n.content.partition("\n")
            if not settings.smtp_host:
                n.status = "non_envoye_smtp_absent"
            else:
                n.attempts = (n.attempts or 0) + 1
                try:
                    _send(settings, n.recipient, subject, body)
                    n.status = "envoye"
                except Exception as exc:  # noqa: BLE001 - toute erreur d'envoi doit finir en « echec », jamais en suspens
                    n.status = "echec"
                    audit.record(db, "keryx", "notification.failed", "notification", n.id, n.tenant_id,
                                 {"error": type(exc).__name__})
            n.ts = utcnow()
            audit.record(db, "keryx", "notification.send", "notification", n.id, n.tenant_id,
                         {"status": n.status, "recipient": n.recipient})
        echecs = db.scalars(select(Notification).where(Notification.id.in_(notification_ids), Notification.canal_id.is_(None),
                                                       Notification.status.in_(ECHECS_NOMINAL))).all()
        secours = [s.id for n in echecs for s in [queue_secours(db, settings, n)] if s]
        db.commit()
    finally:
        db.close()
    if secours:
        from .astreinte import send_pending as send_oncall
        send_oncall(session_factory, settings, secours)


def queue_secours(db: DbSession, settings: Settings, n: Notification) -> Notification | None:
    """Moyen secondaire (PDIS IV.2.3.b) : le courriel d'un ticket a échoué ; le canal secondaire du client reçoit le
    même contenu (numéro du ticket et lien), une seule fois par ticket."""
    from .astreinte import _channel
    if n.ticket_id is None:
        return None
    tenant = db.get(Tenant, n.tenant_id)
    canal = _channel(db, tenant.notif_secours_canal_id) if tenant else None
    if canal is None or db.scalars(select(Notification).where(Notification.ticket_id == n.ticket_id,
                                                               Notification.motif == "secours")).first():
        return None
    ticket = db.get(Ticket, n.ticket_id)
    subject, body = message_for(settings, ticket)
    msg = {"subject": subject, "text": f"{subject}\n{body}",
           "data": {"type": "keryx.notification", "ticket": ticket.ref, "url": f"{settings.public_url}/tickets/{ticket.ref}"}}
    import json
    s = Notification(tenant_id=tenant.id, ticket_id=ticket.id, channel=canal.kind[:16], recipient=canal.name[:200],
                     content=json.dumps(msg, ensure_ascii=False), status="en_attente", canal_id=canal.id, motif="secours")
    db.add(s)
    db.flush()
    audit.record(db, "keryx", "notification.secours", "ticket", ticket.ref, tenant.id,
                 {"canal": canal.name, "echec_nominal": n.status})
    return s


def retry_failed(session_factory, settings: Settings, now=None) -> int:
    """Relance les courriels en échec, avec un délai croissant (2^essais minutes) et un nombre d'essais borné.
    Chaque tentative reste inscrite au registre des notifications [PDIS IV.2.3.h, j]. Renvoie le nombre relancé."""
    from datetime import timedelta
    if not settings.smtp_host:
        return 0
    now = now or utcnow()
    db = session_factory()
    try:
        rows = db.scalars(select(Notification).where(Notification.status == "echec", Notification.canal_id.is_(None),
                                                     Notification.attempts < settings.notify_max_attempts)).all()
        due = [n.id for n in rows if as_utc(n.ts) + timedelta(minutes=2 ** (n.attempts or 1)) <= now]
        claimed = []
        for i in due:  # prise atomique : un seul worker relance chaque courriel
            if db.execute(update(Notification).where(Notification.id == i, Notification.status == "echec")
                          .values(status="en_attente")).rowcount:
                claimed.append(i)
        db.commit()
        due = claimed
    finally:
        db.close()
    send_pending(session_factory, settings, due)
    return len(due)
