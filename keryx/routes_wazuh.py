"""Contexte Wazuh sur la fiche d'un ticket : lecture des événements voisins dans l'indexeur, conservation comme preuve.

[PDIS IV.2.1.aa contexte rattaché ; PRIS VI.5.3.c registre des informations collectées ; PRIS VI.2.4 ; ISO/IEC 27037 ;
PDIS IV.3.8.g cloisonnement ; PDIS IV.3.9.c journalisation ; PDIS IV.3.9.d à h : l'Admin règle l'accès mais ne lit rien ;
RFC 6585 (429) ; ADR-0021]
Réservé à l'analyste et au manager affectés au client du ticket. Désactivé tant que le client n'est pas réglé
(Administration > Clients). La lecture n'écrit que dans le journal d'audit (jamais le contenu) ; rien d'autre n'est
enregistré tant que l'analyste ne demande pas la conservation.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Literal

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import attachments as att
from . import audit
from . import wazuh_context as wz
from .ids import as_utc, parse_timestamp_strict, utcnow
from .models import TLP, Attachment, CustodyEvent, Tenant, User
from .s3store import StorageError

log = logging.getLogger("keryx.wazuh")


class ContextIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    before: Literal[5, 10, 15]
    after: Literal[5, 10, 15]


class KeepIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict
    token: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = Field(min_length=3, max_length=5000)
    sensitivity: str | None = Field(default=None, max_length=20)


def register(app, ctx) -> None:
    get_db, current_user, commit, settings, box = ctx.get_db, ctx.current_user, ctx.commit, ctx.settings, ctx.box
    time_field = wz.validate_time_field(settings.wazuh_time_field)   # refus au démarrage plutôt qu'à la première lecture
    key = wz.seal_key(settings.secret_key)
    user_limiter = ctx.limiter("wazuh_context_user", settings.wazuh_context_user_limit, 60)
    client_limiter = ctx.limiter("wazuh_context_client", settings.wazuh_context_client_limit, 60)

    def team_guard(user: User = Depends(current_user), db: DbSession = Depends(get_db)) -> None:
        """Contrôle de rôle placé AVANT la validation du corps : un client ou un Admin reçoit 403, jamais le détail du
        schéma. La tentative d'un Admin est tracée, comme toute tentative d'accès au contenu d'un ticket."""
        if user.role == "admin":
            audit.record(db, user.username, "ticket.access_denied", "ticket", None, None, {"role": "admin", "objet": "contexte_wazuh"})
            commit(db)
            raise HTTPException(403, "Le rôle Admin n'a pas accès au contenu des tickets.")
        ctx.require_role(user, "analyst", "manager")

    def indexer_config(tenant: Tenant) -> wz.IndexerConfig:
        if not wz.context_configured(tenant):
            raise HTTPException(409, "Le contexte Wazuh n'est pas configuré pour ce client.")
        try:
            endpoint = wz.parse_indexer_url(tenant.wazuh_indexer_url, settings.wazuh_allow_loopback)
            username = box.decrypt(tenant.wazuh_indexer_user, f"wazuh_indexer_user:{tenant.id}")
            password = box.decrypt(tenant.wazuh_indexer_password, f"wazuh_indexer_password:{tenant.id}")
        except wz.ConfigError as exc:   # réglage devenu inacceptable (règle de sortie durcie depuis la saisie)
            raise HTTPException(409, f"Le réglage de l'indexeur Wazuh de ce client est refusé : {exc}") from None
        except Exception:  # noqa: BLE001 - clé maîtresse changée : le compte n'est plus déchiffrable
            log.error("Contexte Wazuh : compte de lecture indéchiffrable pour le client %s", tenant.key)
            raise HTTPException(409, "Le compte de lecture de l'indexeur Wazuh n'est plus lisible : un Admin doit le ressaisir.") from None
        return wz.IndexerConfig(endpoint=endpoint, username=username, password=password,
                                tls_verify=tenant.wazuh_tls_verify, ca_pem=tenant.wazuh_ca_pem,
                                index_pattern=tenant.wazuh_index_pattern or wz.DEFAULT_INDEX_PATTERN,
                                time_field=time_field, allow_loopback=settings.wazuh_allow_loopback)

    @app.post("/api/v1/tickets/{ref}/wazuh-context", dependencies=[Depends(team_guard)])
    def wazuh_context(ref: str, body: ContextIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Événements du MÊME agent autour de l'alerte d'origine : `before` plus récents avant, `after` plus anciens
        après. Affichage seul : la réponse porte un sceau qui permettra, sur demande, de conserver exactement ce jeu."""
        t = ctx.load_ticket(db, user, ref)
        tenant = db.get(Tenant, t.tenant_id)
        cfg = indexer_config(tenant)
        if not t.agent_id:
            raise HTTPException(409, "Ce ticket ne porte pas d'agent Wazuh : le contexte ne peut pas être borné à un agent.")
        if not user_limiter.allow(user.id, db) or not client_limiter.allow(tenant.id, db):
            raise HTTPException(429, "Trop de récupérations de contexte, réessayez dans une minute.")
        alert_id, alert_at, payload = wz.origin_alert(db, t)
        origin = "alerte brute conservée" if payload is not None else "ticket (alerte brute non conservée)"
        pivot = alert_at or as_utc(t.detected_at)
        alert_entry = wz.entry_from_source(payload) if payload is not None else wz.entry_from_source({
            "timestamp": pivot.isoformat(), "rule": {"id": t.rule_id, "level": t.rule_level, "description": t.rule_description},
            "agent": {"id": t.agent_id, "name": t.agent_name}})
        ticket_ref, tenant_id, tenant_key, agent_id = t.ref, t.tenant_id, tenant.key, t.agent_id
        window = {"before": body.before, "after": body.after}
        # Aucune transaction ouverte pendant l'appel sortant (SQLite : la session tiendrait le verrou d'écriture).
        db.commit()
        try:
            found = wz.fetch(cfg, agent_id, pivot, alert_id, body.before, body.after)
        except wz.IndexerError as exc:
            log.warning("Contexte Wazuh : lecture de l'indexeur du client %s en échec (%s)", tenant_key, exc.reason)
            audit.record(db, user.username, "ticket.wazuh_context_failed", "ticket", ticket_ref, tenant_id,
                         {**window, "erreur": exc.reason})
            commit(db)
            raise HTTPException(exc.status, exc.message) from None
        if found.dropped:
            log.warning("Contexte Wazuh : %d événement(s) hors périmètre écarté(s) pour le client %s", found.dropped, tenant_key)
        doc = wz.build_document(ticket_ref=ticket_ref, client_key=tenant_key, fetched_at=utcnow(), fetched_by=user.username,
                                cfg=cfg, agent_id=agent_id, alert_id=alert_id, alert_at=pivot, alert_source=origin,
                                alert_entry=alert_entry, before=body.before, after=body.after, context=found)
        digest = hashlib.sha256(wz.document_bytes(doc)).hexdigest()
        # Audit : qui, quel ticket, quelle fenêtre, combien de résultats. Jamais le contenu des événements.
        audit.record(db, user.username, "ticket.wazuh_context", "ticket", ticket_ref, tenant_id,
                     {**window, "resultats": len(found.before) + len(found.after), "avant": len(found.before),
                      "apres": len(found.after), "ecartes": found.dropped})
        commit(db)
        return {"document": doc, "sha256": digest, "token": wz.seal(key, tenant_id, ticket_ref, user.username, digest)}

    @app.post("/api/v1/tickets/{ref}/wazuh-context/keep", status_code=201, dependencies=[Depends(team_guard)])
    def wazuh_context_keep(ref: str, body: KeepIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Conserve comme preuve le jeu que l'analyste vient de lire : pièce interne (jamais visible du client), empreinte
        SHA-256, registre de collecte, chaîne de possession, même stockage que les autres pièces [PRIS VI.5.3.c]."""
        t = ctx.load_ticket(db, user, ref)
        ctx.require_open(t)  # chaîne de possession figée sur un ticket clos, comme pour un dépôt [ISO/IEC 27037]
        tenant = db.get(Tenant, t.tenant_id)
        sensitivity = body.sensitivity or t.tlp
        if sensitivity not in TLP:
            raise HTTPException(422, f"Sensibilité attendue parmi : {', '.join(TLP)}.")
        try:
            raw = wz.document_bytes(body.document)
        except (TypeError, ValueError, RecursionError):
            raise HTTPException(422, "Jeu de contexte illisible.") from None
        if len(raw) > min(wz.MAX_DOCUMENT_BYTES, (tenant.max_attachment_mb or 20) * 1024 * 1024, settings.max_attachment_bytes):
            raise HTTPException(413, "Jeu de contexte trop volumineux.")
        digest = hashlib.sha256(raw).hexdigest()
        # Le sceau prouve que ce contenu est, à l'octet près, celui que Keryx a lu dans l'indexeur pour cet analyste et
        # ce ticket : ce que le navigateur renvoie n'est jamais cru sur parole.
        if not hmac.compare_digest(wz.seal(key, t.tenant_id, t.ref, user.username, digest), body.token):
            audit.record(db, user.username, "ticket.wazuh_context_keep_refused", "ticket", t.ref, t.tenant_id, {"motif": "sceau"})
            commit(db)
            raise HTTPException(409, "Ce jeu n'est pas celui que Keryx a récupéré pour vous sur ce ticket : récupérez-le de nouveau.")
        doc = body.document
        fetched_at = parse_timestamp_strict(doc.get("fetched_at"))
        if fetched_at is None or utcnow() - fetched_at > wz.TOKEN_TTL:
            raise HTTPException(409, "Ce jeu a été récupéré il y a plus de 30 minutes : récupérez-le de nouveau avant de le conserver.")
        if db.scalars(select(Attachment.id).where(Attachment.ticket_id == t.id, Attachment.sha256 == digest).limit(1)).first():
            raise HTTPException(409, "Ce jeu est déjà conservé dans le registre des preuves de ce ticket.")
        source, requested = doc.get("source") or {}, doc.get("requested") or {}
        count = len(doc.get("before") or []) + len(doc.get("after") or [])
        method = (f"{wz.METHOD_LABEL} : API _search sur {source.get('indexer')}, index {source.get('index_pattern')}, "
                  f"agent {source.get('agent_id')}, {requested.get('before')} avant et {requested.get('after')} après "
                  f"l'alerte {(doc.get('alert') or {}).get('id') or 'du ticket'}")[:500]
        status, detail = att.scan(raw, settings)
        quarantined = status == "quarantaine"
        try:
            storage = att.store(settings, raw, quarantined)
        except StorageError as exc:
            log.error("Stockage des pièces : %s", exc)
            raise HTTPException(502, "Le stockage des pièces est indisponible : la pièce n'a pas été enregistrée.") from None
        try:
            a = Attachment(
                ticket_id=t.id, tenant_id=t.tenant_id, kind="fichier",
                filename=att.safe_filename(f"contexte-wazuh-{t.ref}-{fetched_at.strftime('%Y%m%dT%H%M%SZ')}.json"),
                storage_name=storage, content_type="application/json", size=len(raw), sha256=digest,
                description=body.description, collected_at=fetched_at, method=method, sensitivity=sensitivity,
                scan_status=status, scan_detail=detail, visible_client=False, uploaded_by=user.id)
            db.add(a)
            db.flush()
            db.add(CustodyEvent(attachment_id=a.id, actor=user.username, action="depot",
                                reason="jeu lu par Keryx dans l'indexeur Wazuh, conservé à la demande de l'analyste"))
            ctx.event(db, t, user, "piece_jointe", {"id": a.id, "fichier": a.filename, "sha256": a.sha256,
                                                    "antivirus": status, "origine": "indexeur Wazuh"})
            audit.record(db, user.username, "ticket.wazuh_context_keep", "ticket", t.ref, t.tenant_id,
                         {"piece": a.id, "sha256": digest, "before": requested.get("before"), "after": requested.get("after"),
                          "resultats": count})
            commit(db)
        except BaseException:
            att.destroy(settings, storage, quarantined)  # pas de fichier orphelin si la base échoue
            raise
        return ctx.attachment_view(a)
