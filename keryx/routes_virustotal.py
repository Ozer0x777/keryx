"""Recherche d'empreinte sur VirusTotal : clé d'API de l'utilisateur (profil) et recherche depuis la fiche d'un ticket.

[PRIS IV.3.q codes malveillants ; PDIS IV.2.1.q qualification ; PRIS VI.5.3.d registre des actions ; ISO/IEC 27037
(chaîne de possession) ; PDIS IV.3.8.g cloisonnement ; PDIS IV.3.9.c journalisation ; PDIS IV.3.9.d à h : l'Admin ne voit
ni la clé ni les recherches ; ISO/IEC 27002:2022 8.24 (secrets, via ADR-0006) ; RFC 6585 (429) ; ADR-0022]
DÉROGATION à « aucun service externe » (ADR-0022) : seule une empreinte sort, jamais un fichier. Réservé à l'analyste
et au manager affectés au client du ticket. Disponible par défaut ; `KERYX_VIRUSTOTAL_ENABLED=false` coupe tout.
Chaque recherche aboutie (fichier connu ou inconnu de VirusTotal) est inscrite au registre `hash_lookups`, au registre
des actions du ticket (événement interne), à l'audit et, si l'empreinte est celle d'une pièce, à sa chaîne de
possession. Un échec n'inscrit qu'une entrée d'audit.
"""
from __future__ import annotations

import json
import logging
from typing import Literal

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import attachments as att
from . import audit
from . import virustotal as vt
from .ids import rfc3339
from .models import Attachment, CustodyEvent, HashLookup, RawAlert, Ticket, User, Tenant
from .wazuh_context import clean_text

log = logging.getLogger("keryx.virustotal")

UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
MAX_LOOKUPS_SHOWN = 50
# Pièce produite par Keryx lui-même (jeu de contexte Wazuh conservé, ADR-0021) : son empreinte ne désigne aucun fichier
# qui existe hors de Keryx, la chercher n'apprendrait rien.
KERYX_DOCUMENT = "application/json"
ORIGINS = {"recue": "fichier reçu, avant ré-encodage de l'image", "piece": "pièce conservée", "declaree": "empreinte déclarée"}


class KeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_key: str = Field(max_length=256)


class LookupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["piece", "alerte", "saisie"]
    attachment_id: str | None = Field(default=None, pattern=UUID)
    hash: str | None = Field(default=None, pattern=vt.HASH_PATTERN)


def lookup_view(row: HashLookup) -> dict:
    return {"id": row.id, "hash": row.hash, "hash_type": row.hash_type, "source_type": row.source_type,
            "source_id": row.source_id, "status": row.status, "summary": row.summary or {}, "actor": row.actor,
            "created_at": rfc3339(row.created_at), "url": vt.gui_url(row.hash)}


def ticket_view(db: DbSession, t: Ticket) -> dict:
    """Bloc « virustotal » de la fiche, pour l'équipe seulement (jamais le client, jamais l'Admin) : les recherches
    déjà faites sur ce ticket, de la plus récente à la plus ancienne."""
    rows = db.scalars(select(HashLookup).where(HashLookup.ticket_id == t.id)
                      .order_by(HashLookup.created_at.desc(), HashLookup.id.desc()).limit(MAX_LOOKUPS_SHOWN)).all()
    return {"lookups": [lookup_view(r) for r in rows], "autorise": bool(db.get(Tenant, t.tenant_id).virustotal_autorise)}


def piece_hash(db: DbSession, a: Attachment) -> tuple[str, str]:
    """(empreinte, origine) à chercher pour une pièce. C'est le serveur qui la détermine, jamais le navigateur.
    - fichier (archive) : l'empreinte de la pièce, qui est celle du fichier reçu ; une pièce en quarantaine garde
      l'empreinte de l'original (c'est l'archive chiffrée de quarantaine qui est stockée, pas elle qui est empreinte) ;
    - image : Keryx la ré-encode, donc l'empreinte de la pièce est celle d'un fichier qui n'existe que dans Keryx.
      Quand l'empreinte du fichier REÇU est connue (motif de l'événement de dépôt), c'est elle qui est cherchée ;
    - preuve externe : l'empreinte déclarée par l'analyste."""
    if a.kind == "preuve_externe":
        return a.sha256, "declaree"
    if a.kind == "image":
        first = db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == a.id, CustodyEvent.action == "depot")
                           .order_by(CustodyEvent.ts, CustodyEvent.id).limit(1)).first()
        received = vt.received_hash(first.reason if first else None)
        if received:
            return received, "recue"
    return a.sha256, "piece"


def searchable(a: Attachment) -> bool:
    return a.content_type != KERYX_DOCUMENT and vt.hash_kind(a.sha256) == "sha256"


def alert_candidates(db: DbSession, t: Ticket) -> list[dict]:
    """Empreintes présentes dans les alertes brutes conservées du ticket (bornées, sans doublon)."""
    rows = db.scalars(select(RawAlert).where(RawAlert.ticket_id == t.id)
                      .order_by(RawAlert.received_at, RawAlert.id).limit(vt.MAX_ALERTS)).all()
    out: dict[str, dict] = {}
    for r in rows:
        try:
            payload = json.loads(r.payload)
        except (ValueError, RecursionError):
            continue
        for c in vt.extract_alert_hashes(payload):
            if c["hash"] not in out and len(out) < vt.MAX_CANDIDATES:
                out[c["hash"]] = {"source": "alerte", **c, "alert": r.id, "wazuh_id": clean_text(r.wazuh_id, 64),
                                  "received_at": rfc3339(r.received_at)}
    return list(out.values())


def register(app, ctx) -> None:
    get_db, current_user, commit, settings, box = ctx.get_db, ctx.current_user, ctx.commit, ctx.settings, ctx.box
    client = None
    if settings.virustotal_enabled:
        try:   # refus au démarrage plutôt qu'à la première recherche
            base_url = vt.parse_base_url(settings.virustotal_url, settings.virustotal_allow_loopback)
            client = vt.Client(base_url, vt.parse_proxy(settings.virustotal_proxy))
        except vt.ConfigError as exc:
            raise RuntimeError(str(exc)) from None
        if base_url != vt.OFFICIAL_URL:
            log.warning("KERYX_VIRUSTOTAL_URL est réglé : les empreintes et les clés d'API des utilisateurs partent vers %s, "
                        "pas vers VirusTotal. Réglage d'essai, à retirer en production.", base_url)
    user_limiter = ctx.limiter("virustotal_user", settings.virustotal_user_limit, 60)
    client_limiter = ctx.limiter("virustotal_client", settings.virustotal_client_limit, 60)

    def profile_guard(user: User = Depends(current_user)) -> None:
        """La clé VirusTotal n'existe que pour l'analyste et le manager : client et Admin reçoivent 403 avant toute
        validation du corps."""
        ctx.require_role(user, "analyst", "manager")

    def team_guard(user: User = Depends(current_user), db: DbSession = Depends(get_db)) -> None:
        """Même garde que le contexte Wazuh, placée AVANT la validation du corps : un client ou un Admin reçoit 403,
        jamais le détail du schéma. La tentative d'un Admin est tracée."""
        if user.role == "admin":
            audit.record(db, user.username, "ticket.access_denied", "ticket", None, None, {"role": "admin", "objet": "virustotal"})
            commit(db)
            raise HTTPException(403, "Le rôle Admin n'a pas accès au contenu des tickets.")
        ctx.require_role(user, "analyst", "manager")

    def enabled_guard() -> None:
        if not settings.virustotal_enabled or client is None:
            raise HTTPException(409, "La recherche sur VirusTotal est désactivée sur cette instance.")

    # ---------------------------------------------------------------- profil : la clé de l'utilisateur
    @app.get("/api/v1/me/virustotal", dependencies=[Depends(profile_guard)])
    def vt_key_state(user: User = Depends(current_user)):
        """État seulement : la clé elle-même n'est jamais renvoyée, pas même en partie."""
        return {"configured": bool(user.vt_api_key), "enabled": bool(settings.virustotal_enabled and client)}

    @app.put("/api/v1/me/virustotal", dependencies=[Depends(profile_guard), Depends(enabled_guard)])
    def vt_key_set(body: KeyIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Enregistre ou remplace la clé. Sa forme est contrôlée ; elle n'est PAS essayée auprès de VirusTotal (aucun
        appel sortant à l'enregistrement) : une clé refusée se voit à la première recherche."""
        try:
            key = vt.validate_api_key(body.api_key)
        except vt.ConfigError as exc:
            raise HTTPException(422, str(exc)) from None
        replaced = bool(user.vt_api_key)
        user.vt_api_key = box.encrypt(key, f"vt_api_key:{user.id}")
        audit.record(db, user.username, "auth.vt_key_set", "user", user.id, None, {"remplacement": replaced})
        commit(db)
        return {"configured": True, "enabled": True}

    @app.delete("/api/v1/me/virustotal", dependencies=[Depends(profile_guard)])
    def vt_key_remove(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Retire la clé. Reste possible quand la fonction est coupée : un secret doit toujours pouvoir être effacé."""
        if user.vt_api_key:
            user.vt_api_key = None
            audit.record(db, user.username, "auth.vt_key_removed", "user", user.id)
            commit(db)
        return {"configured": False, "enabled": bool(settings.virustotal_enabled and client)}

    # ---------------------------------------------------------------- fiche d'un ticket
    @app.get("/api/v1/tickets/{ref}/virustotal/hashes", dependencies=[Depends(team_guard), Depends(enabled_guard)])
    def vt_candidates(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Empreintes du ticket qui peuvent être cherchées : pièces et preuves externes (empreinte déterminée par le
        serveur), empreintes lues dans les alertes brutes. Rien ne sort de Keryx ici."""
        t = ctx.load_ticket(db, user, ref)
        atts = db.scalars(select(Attachment).where(Attachment.ticket_id == t.id).order_by(Attachment.created_at)).all()
        pieces = []
        for a in atts:
            if not searchable(a):
                continue
            digest, origin = piece_hash(db, a)
            pieces.append({"source": "preuve_externe" if a.kind == "preuve_externe" else "piece", "attachment_id": a.id,
                           "filename": a.filename, "hash": digest, "hash_type": "sha256", "origin": origin,
                           "quarantine": att.isole(a.scan_status)})
        alerts = alert_candidates(db, t)
        # Les empreintes des alertes sont du contenu que la lecture du ticket ne montre pas telles quelles : tracé.
        audit.record(db, user.username, "ticket.virustotal_hashes", "ticket", t.ref, t.tenant_id,
                     {"pieces": len(pieces), "alertes": len(alerts)})
        commit(db)
        return {"configured": bool(user.vt_api_key), "pieces": pieces, "alerts": alerts}

    @app.post("/api/v1/tickets/{ref}/virustotal", status_code=201, dependencies=[Depends(team_guard), Depends(enabled_guard)])
    def vt_lookup(ref: str, body: LookupIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Cherche UNE empreinte sur VirusTotal avec la clé de l'utilisateur. Source « piece » : le serveur prend
        l'empreinte de la pièce lui-même ; « alerte » : l'empreinte doit figurer dans une alerte brute du ticket ;
        « saisie » : empreinte saisie par l'analyste."""
        t = ctx.load_ticket(db, user, ref)
        if not db.get(Tenant, t.tenant_id).virustotal_autorise:
            raise HTTPException(403, "Le client n'a pas donné son accord à la recherche d'empreintes chez VirusTotal "
                                     "(PDIS IV.1.g) : le manager l'enregistre dans « Politique des clients ».")
        attachment, origin = None, None
        if body.source == "piece":
            if body.hash is not None or not body.attachment_id:
                raise HTTPException(422, "Pour une pièce, indiquer seulement son identifiant : son empreinte est prise par le serveur.")
            attachment = db.get(Attachment, body.attachment_id)
            if attachment is None or attachment.ticket_id != t.id:
                raise HTTPException(404, "Pièce introuvable.")
            if not searchable(attachment):
                raise HTTPException(422, "Cette pièce est un document produit par Keryx : son empreinte ne désigne aucun fichier connu ailleurs.")
            digest, origin = piece_hash(db, attachment)
            source_type, source_id = ("preuve_externe" if attachment.kind == "preuve_externe" else "piece"), attachment.id
        else:
            if body.attachment_id is not None or not body.hash:
                raise HTTPException(422, "Indiquer l'empreinte à chercher (SHA-256 ou SHA-1, en minuscules).")
            digest, source_type, source_id = body.hash, body.source, None
            if body.source == "alerte":
                match = next((c for c in alert_candidates(db, t) if c["hash"] == digest), None)
                if match is None:
                    raise HTTPException(422, "Cette empreinte ne figure dans aucune alerte brute conservée de ce ticket.")
                source_id = match["alert"]
        kind = vt.hash_kind(digest)
        if kind is None:   # empreinte de pièce qui n'en a pas la forme (ne devrait pas exister) : rien ne sort
            raise HTTPException(422, "Empreinte invalide : SHA-256 ou SHA-1 attendu.")
        if not user.vt_api_key:
            raise HTTPException(409, "Aucune clé d'API VirusTotal n'est enregistrée pour votre compte : ajoutez-la dans votre profil.")
        try:
            api_key = box.decrypt(user.vt_api_key, f"vt_api_key:{user.id}")
        except Exception:  # noqa: BLE001 - clé maîtresse changée : la clé n'est plus déchiffrable
            log.error("VirusTotal : clé d'API indéchiffrable pour le compte %s", user.username)
            raise HTTPException(409, "Votre clé d'API VirusTotal n'est plus lisible : ressaisissez-la dans votre profil.") from None
        if not user_limiter.allow(user.id, db) or not client_limiter.allow(t.tenant_id, db):
            raise HTTPException(429, "Trop de recherches VirusTotal, réessayez dans une minute.")
        trace = {"empreinte": digest, "type": kind, "source": source_type}
        if attachment is not None:
            trace["piece"] = attachment.id
        # Aucune transaction ouverte pendant l'appel sortant (SQLite : la session tiendrait le verrou d'écriture).
        db.commit()
        try:
            report = client.file_report(digest, api_key)
        except vt.VirusTotalError as exc:
            log.warning("VirusTotal : recherche en échec pour %s (%s)", user.username, exc.reason)
            audit.record(db, user.username, "ticket.virustotal_lookup_failed", "ticket", t.ref, t.tenant_id,
                         {**trace, "erreur": exc.reason})
            commit(db)
            raise HTTPException(exc.status, exc.message) from None
        row = HashLookup(ticket_id=t.id, tenant_id=t.tenant_id, hash=digest, hash_type=kind, source_type=source_type,
                         source_id=source_id, status=report.status, summary=report.summary, actor=user.username)
        db.add(row)
        stats = report.summary.get("stats") or {}
        details = {**trace, "statut": report.status}
        if report.status == "trouve":
            details.update({"malveillant": stats.get("malicious", 0), "suspect": stats.get("suspicious", 0),
                            "inoffensif": stats.get("harmless", 0), "non_detecte": stats.get("undetected", 0)})
        if attachment is not None:
            outcome = "fichier connu de VirusTotal" if report.status == "trouve" else "fichier inconnu de VirusTotal"
            db.add(CustodyEvent(attachment_id=attachment.id, actor=user.username, action="analyse_virustotal",
                                reason=f"empreinte {digest} ({ORIGINS[origin]}) cherchée sur VirusTotal : {outcome}"))
        # Événement interne du ticket (jamais visible du client) et entrée d'audit « ticket.virustotal_lookup » :
        # empreinte, statut, compteurs. Jamais la clé, jamais les textes renvoyés par VirusTotal.
        ctx.event(db, t, user, "virustotal_lookup", details)
        commit(db)
        return {**lookup_view(row), "origin": origin}
