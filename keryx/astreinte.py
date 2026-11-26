"""Astreinte de l'équipe et escalade (ADR-0032, partie 2).

Un ticket ouvert d'une criticité choisie par le manager prévient le canal d'astreinte du client ; sans action humaine
de l'équipe au bout du délai réglé pour cette criticité, Keryx prévient une fois le canal d'escalade, puis s'arrête.
Les canaux sont déclarés par l'Admin (webhook JSON générique, webhook Mattermost / Slack, webhook Microsoft Teams par
l'application Workflows, courriel de l'équipe).

Envoi borné, même règle de sortie que le connecteur Wazuh (ADR-0021) :
- HTTPS uniquement, pas d'identifiants dans l'URL, aucune redirection suivie, aucun mandataire d'environnement ;
- le nom est résolu ici, chaque adresse est contrôlée (boucle locale, lien local, métadonnées, multidiffusion,
  réservées : refusées), et la connexion part vers l'adresse contrôlée ; les adresses privées sont acceptées (un
  Mattermost interne) ;
- délai court, réponse lue et bornée, seul le code de réponse est retenu : Keryx ne prétend pas savoir si le message a
  été lu.
Minimisation : le message porte la référence, le client, la criticité et le lien ; le titre seulement si le canal le
prévoit. L'adresse d'un webhook (qui contient souvent son jeton) et le secret de signature sont chiffrés au repos.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import re
import smtplib
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from . import audit
from .config import Settings
from .ids import as_utc, rfc3339, utcnow
from .models import OnCallChannel, Notification, Tenant, Ticket, TicketEvent
from .security import SecretBox
from .wazuh_context import address_refusal

log = logging.getLogger("keryx.astreinte")

KINDS = ("webhook_json", "webhook_mattermost", "webhook_teams", "email")
CRITICITES = ("Critique", "Élevée", "Moyenne", "Faible")
DELAIS_DEFAUT = {"Critique": 15, "Élevée": 30, "Moyenne": 60, "Faible": 120}
OPEN = ("nouveau", "en_evaluation", "en_reponse")
TIMEOUT_S = 10
MAX_RESPONSE_BYTES = 64 * 1024
MAX_ATTEMPTS = 5

_EMAIL = re.compile(r"^[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")


class ChannelError(ValueError):
    """Réglage de canal refusé (message affichable)."""


class DeliveryError(Exception):
    def __init__(self, reason: str, http_status: int | None = None):
        super().__init__(reason)
        self.reason, self.http_status = reason, http_status


# ---------------------------------------------------------------- réglages
@dataclass(frozen=True)
class Webhook:
    host: str
    port: int
    target: str          # chemin et requête

    @property
    def label(self) -> str:
        return f"https://{self.host}{'' if self.port == 443 else f':{self.port}'}/…"


def parse_webhook(value: str) -> Webhook:
    v = (value or "").strip()
    if not v or len(v) > 1000:
        raise ChannelError("Adresse du webhook vide ou trop longue (1000 caractères maximum).")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in v):
        raise ChannelError("L'adresse du webhook contient un espace ou un caractère de contrôle.")
    u = urlsplit(v)
    if u.scheme != "https":
        raise ChannelError("Le webhook doit être en HTTPS.")
    if u.username or u.password or "@" in u.netloc:
        raise ChannelError("Pas d'identifiants dans l'adresse du webhook.")
    if u.fragment:
        raise ChannelError("Pas de fragment (#) dans l'adresse du webhook.")
    host = (u.hostname or "").rstrip(".")
    try:
        port = u.port or 443
    except ValueError as exc:
        raise ChannelError("Port du webhook invalide.") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise ChannelError("Nom d'hôte du webhook invalide.")
    target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return Webhook(host, port, target)


def check_target(kind: str, target: str) -> str:
    """Contrôle l'adresse d'un canal et renvoie son libellé affichable (jamais l'adresse complète d'un webhook)."""
    if kind not in KINDS:
        raise ChannelError(f"Type de canal attendu parmi : {', '.join(KINDS)}.")
    if kind == "email":
        t = (target or "").strip()
        if not _EMAIL.match(t):
            raise ChannelError("Adresse courriel de l'équipe invalide.")
        return t
    return parse_webhook(target).label


# ---------------------------------------------------------------- messages
def message(settings: Settings, motif: str, ticket: Ticket, tenant: Tenant, channel: OnCallChannel,
            delai_min: int | None = None) -> dict:
    """Contenu minimal : référence, client, criticité, lien ; le titre si le canal le prévoit."""
    link = f"{settings.public_url}/tickets/{ticket.ref}"
    crit = ticket.criticite_initiale
    if motif == "escalade":
        subject = f"[Keryx] ESCALADE {ticket.ref} ({crit}, {tenant.key}) : sans prise en charge depuis {delai_min} min"
        text = (f"[Keryx] ESCALADE : ticket {ticket.ref} ({crit}, client {tenant.key}) sans prise en charge depuis "
                f"{delai_min} min. {link}")
    else:
        subject = f"[Keryx] Astreinte {ticket.ref} ({crit}, {tenant.key}) : nouveau ticket"
        text = f"[Keryx] Astreinte : nouveau ticket {ticket.ref} ({crit}, client {tenant.key}). {link}"
    data = {"type": f"keryx.{motif}", "ticket": ticket.ref, "client": tenant.key, "criticite": crit, "url": link}
    if motif == "escalade":
        data["delai_minutes"] = delai_min
    if channel.include_title:
        text += f"\n{ticket.title}"
        data["titre"] = ticket.title
    return {"subject": subject, "text": text, "data": data}


def teams_card(msg: dict) -> dict:
    """Carte adaptative attendue par un flux Microsoft Teams Workflows (« Publier dans un canal à la réception d'une
    requête webhook ») ; les anciens connecteurs Office 365 sont retirés par Microsoft."""
    title, _, rest = msg["text"].partition(" : ")
    url = msg["data"].get("url")
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True},
                     {"type": "TextBlock", "text": rest.replace(f" {url}", "") if url else rest, "wrap": True}]}
    if url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Ouvrir dans Keryx", "url": url}]
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                 "contentUrl": None, "content": card}]}


def body_for(kind: str, msg: dict, now) -> bytes:
    if kind == "webhook_mattermost":
        payload = {"text": msg["text"]}       # Mattermost et Slack acceptent ce format de webhook entrant
    elif kind == "webhook_teams":
        payload = teams_card(msg)
    else:
        payload = {**msg["data"], "envoye_le": rfc3339(now)}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def signature(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 de « horodatage.corps » : le destinataire vérifie l'origine et refuse un message rejoué."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- envoi
def _tls_context(settings: Settings) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=settings.astreinte_ca_file) if settings.astreinte_ca_file \
        else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _resolve(hook: Webhook, allow_loopback: bool) -> list[str]:
    try:
        infos = socket.getaddrinfo(hook.host, hook.port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise DeliveryError("nom_introuvable") from exc
    addresses = list(dict.fromkeys(i[4][0] for i in infos))
    if not addresses:
        raise DeliveryError("nom_introuvable")
    for a in addresses:
        if address_refusal(a, allow_loopback):
            raise DeliveryError("adresse_refusee")      # une seule adresse refusée refuse l'envoi
    return addresses


def post(settings: Settings, url: str, body: bytes, headers: dict) -> int:
    """POST HTTPS vers une adresse contrôlée ; renvoie le code de réponse. Aucune redirection n'est suivie."""
    hook = parse_webhook(url)
    deadline = time.monotonic() + TIMEOUT_S
    ctx = _tls_context(settings)
    last: Exception | None = None
    for address in _resolve(hook, settings.astreinte_allow_loopback):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock = None
        try:
            sock = socket.create_connection((address.split("%", 1)[0], hook.port), timeout=remaining)
            tls = ctx.wrap_socket(sock, server_hostname=hook.host)
        except ssl.SSLError as exc:
            if sock is not None:
                sock.close()
            raise DeliveryError("tls") from exc
        except OSError as exc:
            if sock is not None:
                sock.close()
            last = exc
            continue
        try:
            conn = http.client.HTTPConnection(hook.host, hook.port, timeout=max(0.1, deadline - time.monotonic()))
            conn.sock = tls
            host_header = f"[{hook.host}]" if ":" in hook.host else hook.host
            conn.request("POST", hook.target, body=body, headers={
                "Host": host_header if hook.port == 443 else f"{host_header}:{hook.port}",
                "Content-Type": "application/json; charset=utf-8", "User-Agent": "Keryx-astreinte",
                "Accept-Encoding": "identity", "Connection": "close", **headers})
            resp = conn.getresponse()
            read = 0
            while read <= MAX_RESPONSE_BYTES:
                if time.monotonic() > deadline:
                    break
                chunk = resp.read1(8192)
                if not chunk:
                    break
                read += len(chunk)
            return resp.status
        except (OSError, http.client.HTTPException) as exc:
            raise DeliveryError("delai" if isinstance(exc, TimeoutError) else "connexion") from exc
        finally:
            tls.close()
    raise DeliveryError("delai" if isinstance(last, TimeoutError) else "injoignable") from last


def _send_mail(settings: Settings, to: str, subject: str, body: str) -> None:
    from .notify import _send
    if not settings.smtp_host:
        raise DeliveryError("smtp_absent")
    try:
        _send(settings, to, subject, body)
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError("smtp") from exc


def deliver(settings: Settings, box: SecretBox, channel: OnCallChannel, msg: dict, now=None) -> int | None:
    """Envoie un message sur un canal. Renvoie le code HTTP (webhook) ou None (courriel) ; lève DeliveryError."""
    now = now or utcnow()
    target = box.decrypt(channel.target_enc, f"canal:{channel.id}")
    if channel.kind == "email":
        _send_mail(settings, target, msg.get("subject") or msg["text"].split(" : ", 1)[0], msg["text"])
        return None
    body = body_for(channel.kind, msg, now)
    headers = {}
    if channel.secret_enc and channel.kind == "webhook_json":
        ts = str(int(now.timestamp()))
        headers = {"X-Keryx-Timestamp": ts,
                   "X-Keryx-Signature": signature(box.decrypt(channel.secret_enc, f"canal-secret:{channel.id}"), ts, body)}
    status = post(settings, target, body, headers)
    if not 200 <= status < 300:
        raise DeliveryError("reponse", status)
    return status


# ---------------------------------------------------------------- file d'envoi
def _channel(db: DbSession, channel_id: str | None) -> OnCallChannel | None:
    c = db.get(OnCallChannel, channel_id) if channel_id else None
    return c if c is not None and c.active else None


def _queue(db: DbSession, settings: Settings, motif: str, ticket: Ticket, tenant: Tenant, channel: OnCallChannel,
           actor: str, delai_min: int | None = None) -> Notification:
    msg = message(settings, motif, ticket, tenant, channel, delai_min)
    n = Notification(tenant_id=tenant.id, ticket_id=ticket.id, channel=channel.kind[:16], recipient=channel.name[:200],
                     content=json.dumps(msg, ensure_ascii=False), status="en_attente", canal_id=channel.id, motif=motif)
    db.add(n)
    db.add(TicketEvent(ticket_id=ticket.id, actor=actor, action=motif, visible_client=False,
                       details={"canal": channel.name, **({"delai_minutes": delai_min} if delai_min else {})}))
    audit.record(db, actor, f"astreinte.{motif}", "ticket", ticket.ref, tenant.id, {"canal": channel.name})
    return n


def queue_new_ticket(db: DbSession, settings: Settings, tenant: Tenant, ticket: Ticket, actor: str) -> list[Notification]:
    """À l'ouverture : prévient l'astreinte du client si la criticité est de celles que le manager a choisies."""
    if not tenant.astreinte_active or ticket.criticite_initiale not in (tenant.astreinte_criticites or []):
        return []
    channel = _channel(db, tenant.astreinte_canal_id)
    if channel is None:
        return []
    ticket.astreinte_at = utcnow()
    return [_queue(db, settings, "astreinte", ticket, tenant, channel, actor)]


def send_pending(session_factory, settings: Settings, notification_ids: list[str]) -> None:
    """Envoie les messages d'astreinte et d'escalade en attente ; chaque tentative est inscrite au registre."""
    if not notification_ids:
        return
    box = SecretBox(settings.secret_key)
    db = session_factory()
    try:
        rows = db.scalars(select(Notification).where(Notification.id.in_(notification_ids),
                                                     Notification.status == "en_attente",
                                                     Notification.canal_id.is_not(None))).all()
        for n in rows:
            channel = db.get(OnCallChannel, n.canal_id)
            n.attempts = (n.attempts or 0) + 1
            n.ts = utcnow()
            if channel is None or not channel.active:
                n.status, n.http_status, reason = "canal_inactif", None, "canal_inactif"
            else:
                try:
                    n.http_status = deliver(settings, box, channel, json.loads(n.content))
                    n.status, reason = "envoye", None
                except DeliveryError as exc:
                    n.status, n.http_status, reason = "echec", exc.http_status, exc.reason
                except Exception as exc:  # noqa: BLE001 - toute erreur d'envoi finit en « echec », jamais en suspens
                    n.status, n.http_status, reason = "echec", None, type(exc).__name__
            audit.record(db, "keryx", "astreinte.envoi", "notification", n.id, n.tenant_id,
                         {"motif": n.motif, "canal": n.recipient, "statut": n.status, "code": n.http_status,
                          **({"erreur": reason} if reason else {})})
        db.commit()
    finally:
        db.close()


def tick(session_factory, settings: Settings, now=None) -> dict:
    """Tâche de fond : escalade des tickets prévenus et non acquittés au-delà du délai, relance des envois en échec."""
    now = as_utc(now) if now else utcnow()
    escalated, retried = [], []
    db = session_factory()
    try:
        rows = db.execute(select(Ticket, Tenant).join(Tenant, Tenant.id == Ticket.tenant_id).where(
            Ticket.status.in_(OPEN), Ticket.acquitted_at.is_(None), Ticket.astreinte_at.is_not(None),
            Ticket.escalade_at.is_(None), Tenant.astreinte_active.is_(True))).all()
        for t, tenant in rows:
            delai = int((tenant.astreinte_delais or DELAIS_DEFAUT).get(t.criticite_initiale)
                        or DELAIS_DEFAUT.get(t.criticite_initiale, 15))
            if as_utc(t.astreinte_at) + timedelta(minutes=delai) > now:
                continue
            channel = _channel(db, tenant.escalade_canal_id)
            if channel is None:
                continue
            # prise atomique : une seule escalade par ticket, même avec plusieurs processus
            if not db.execute(update(Ticket).where(Ticket.id == t.id, Ticket.escalade_at.is_(None))
                              .values(escalade_at=now)).rowcount:
                continue
            escalated.append(_queue(db, settings, "escalade", t, tenant, channel, "keryx", delai))
        db.flush()
        escalated = [n.id for n in escalated]
        failed = db.scalars(select(Notification).where(Notification.canal_id.is_not(None), Notification.status == "echec",
                                                       Notification.attempts < MAX_ATTEMPTS)).all()
        for n in failed:
            if as_utc(n.ts) + timedelta(minutes=2 ** (n.attempts or 1)) > now:
                continue
            if db.execute(update(Notification).where(Notification.id == n.id, Notification.status == "echec")
                          .values(status="en_attente")).rowcount:
                retried.append(n.id)
        db.commit()
    finally:
        db.close()
    send_pending(session_factory, settings, escalated + retried)
    return {"escalades": len(escalated), "relances": len(retried)}
