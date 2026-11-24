"""Parc d'agents Wazuh (ADR-0030) : vue de l'équipe et du client, détail d'un agent, relevé manuel, export, ticket
« agent déconnecté » ouvert à la main. Lecture seule côté Wazuh.

Cloisonnement [PDIS IV.3.8.g] : chaque requête est bornée aux clients de l'utilisateur ; le client ne voit que son parc,
sans les informations internes (nœud du manager, tickets, erreurs techniques du relevé). L'Admin règle l'accès à l'API
(routes_admin) mais ne lit pas le parc.
"""
from __future__ import annotations

import csv
import io
import logging
import threading
from datetime import timedelta

from fastapi import Depends, HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from . import audit
from . import wazuh_agents as wa
from . import wazuh_context as wz
from .ids import as_utc, rfc3339, utcnow
from .ingest import AlertRejected, ingest_alert
from .models import Tenant, Ticket, User, WazuhAgent, WazuhAgentEvent

log = logging.getLogger("keryx.parc")
OPEN = ("nouveau", "en_evaluation", "en_reponse")
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def tenant_lock(tenant_id: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(tenant_id, threading.Lock())


def api_config(settings, box, tenant: Tenant) -> wa.ApiConfig:
    endpoint = wz.parse_indexer_url(tenant.wazuh_api_url, settings.wazuh_allow_loopback)
    return wa.ApiConfig(endpoint=endpoint,
                        username=box.decrypt(tenant.wazuh_api_user, f"wazuh_api_user:{tenant.id}"),
                        password=box.decrypt(tenant.wazuh_api_password, f"wazuh_api_password:{tenant.id}"),
                        tls_verify=tenant.wazuh_tls_verify, ca_pem=tenant.wazuh_ca_pem, group=tenant.wazuh_api_group,
                        allow_loopback=settings.wazuh_allow_loopback)


def indexer_config(settings, box, tenant: Tenant) -> wz.IndexerConfig | None:
    if not wz.context_configured(tenant):
        return None
    return wz.IndexerConfig(endpoint=wz.parse_indexer_url(tenant.wazuh_indexer_url, settings.wazuh_allow_loopback),
                            username=box.decrypt(tenant.wazuh_indexer_user, f"wazuh_indexer_user:{tenant.id}"),
                            password=box.decrypt(tenant.wazuh_indexer_password, f"wazuh_indexer_password:{tenant.id}"),
                            tls_verify=tenant.wazuh_tls_verify, ca_pem=tenant.wazuh_ca_pem,
                            index_pattern=tenant.wazuh_index_pattern or wz.DEFAULT_INDEX_PATTERN,
                            time_field=wz.validate_time_field(settings.wazuh_time_field),
                            allow_loopback=settings.wazuh_allow_loopback)


def refresh_tenant(db: DbSession, settings, box, tenant: Tenant) -> dict:
    """Un relevé complet pour un client : agents par l'API, dernier événement par l'indexeur s'il est relié.
    Un échec est enregistré sur le client (message lisible) et renvoyé ; il ne lève pas."""
    now = utcnow()
    try:
        cfg = api_config(settings, box, tenant)
    except wz.ConfigError as exc:
        tenant.wazuh_agents_error = f"Réglage refusé : {exc}"[:300]
        return {"erreur": tenant.wazuh_agents_error}
    except Exception:  # noqa: BLE001 - clé maîtresse changée : compte indéchiffrable
        tenant.wazuh_agents_error = "Le compte de lecture de l'API Wazuh n'est plus lisible : un Admin doit le ressaisir."
        return {"erreur": tenant.wazuh_agents_error}
    try:
        snap = wa.fetch(cfg)
    except wa.ApiError as exc:
        tenant.wazuh_agents_error = exc.message[:300]
        log.warning("Parc Wazuh : relevé en échec pour %s (%s)", tenant.key, exc.reason)
        return {"erreur": tenant.wazuh_agents_error}
    events = None
    try:
        icfg = indexer_config(settings, box, tenant)
        if icfg is not None:
            events = wa.last_events(icfg, [a["agent_id"] for a in snap.agents][:5000])
    except (wz.IndexerError, wz.ConfigError) as exc:
        log.warning("Parc Wazuh : dernier événement non lu pour %s (%s)", tenant.key, getattr(exc, "reason", exc))
    except Exception:  # noqa: BLE001 - compte de l'indexeur indéchiffrable : le parc reste utile sans
        log.warning("Parc Wazuh : compte de l'indexeur illisible pour %s", tenant.key)
    return wa.store(db, tenant, snap, events, now)


def poll_all(session_factory, settings, box) -> int:
    """Relevé de tous les clients configurés (tâche de fond). Renvoie le nombre de clients relevés."""
    done = 0
    with session_factory() as db:
        ids = [t.id for t in db.scalars(select(Tenant).where(Tenant.wazuh_api_url.is_not(None)))]
    for tid in ids:
        lock = tenant_lock(tid)
        if not lock.acquire(blocking=False):
            continue
        try:
            with session_factory() as db:
                t = db.get(Tenant, tid)
                if t is None or not wa.api_configured(t):
                    continue
                refresh_tenant(db, settings, box, t)
                db.commit()
                done += 1
        except Exception:  # noqa: BLE001 - un client en échec n'arrête pas les autres
            log.exception("Parc Wazuh : relevé interrompu")
        finally:
            lock.release()
    return done


def register(app, ctx) -> None:
    get_db, current_user, commit, settings, box = ctx.get_db, ctx.current_user, ctx.commit, ctx.settings, ctx.box
    refresh_limiter = ctx.limiter("parc_refresh", 2, 60)

    def tenant_for(user: User, key: str | None) -> Tenant:
        if user.role == "admin":
            raise HTTPException(403, "Le rôle Admin règle l'accès à l'API Wazuh mais ne lit pas le parc des clients.")
        mine = sorted(user.tenants, key=lambda t: t.key)
        if not mine:
            raise HTTPException(404, "Aucun client.")
        if not key:
            return mine[0]
        for t in mine:
            if t.key == key.upper():
                return t
        raise HTTPException(404, "Client inconnu.")      # même réponse qu'un client inexistant : rien n'est révélé

    def team_only(user: User) -> None:
        ctx.require_role(user, "analyst", "manager")

    def importance_by_agent(db: DbSession, tenant: Tenant) -> dict[str, str]:
        """Importance connue de chaque agent : celle du ticket le plus récent (label « importance » de l'alerte)."""
        out = {}
        for agent_id, imp in db.execute(select(Ticket.agent_id, Ticket.importance).where(Ticket.tenant_id == tenant.id)
                                        .order_by(Ticket.created_at)).all():
            if agent_id:
                out[agent_id] = imp
        return out

    def open_tickets(db: DbSession, tenant: Tenant) -> dict[str, int]:
        return dict(db.execute(select(Ticket.agent_id, func.count()).where(Ticket.tenant_id == tenant.id,
                               Ticket.status.in_(OPEN)).group_by(Ticket.agent_id)).all())

    def agent_view(a: WazuhAgent, tenant: Tenant, now, team: bool, imp: dict, tickets: dict, events_known: bool) -> dict:
        out = {"id": a.agent_id, "name": a.name, "ip": a.ip,
               "os": " ".join(x for x in (a.os_name, a.os_version) if x) or None,
               "version": a.version, "status": a.status, "status_since": rfc3339(a.status_since),
               "last_keepalive": rfc3339(a.last_keepalive), "registered_at": rfc3339(a.registered_at),
               "last_event_at": rfc3339(a.last_event_at), "groups": a.groups or [], "importance": imp.get(a.agent_id),
               **wa.flags(a, tenant.wazuh_manager_version, now, events_known)}
        if team:
            out.update({"node": a.node, "open_tickets": tickets.get(a.agent_id, 0)})
        return out

    @app.get("/api/v1/parc")
    def parc(client: str | None = None, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        tenant = tenant_for(user, client)
        team = user.role in ("analyst", "manager")
        now = utcnow()
        events_known = wz.context_configured(tenant)
        rows = db.scalars(select(WazuhAgent).where(WazuhAgent.tenant_id == tenant.id).order_by(WazuhAgent.name)).all()
        imp, tickets = importance_by_agent(db, tenant), (open_tickets(db, tenant) if team else {})
        agents = [agent_view(a, tenant, now, team, imp, tickets, events_known) for a in rows]
        versions: dict[str, int] = {}
        for a in agents:
            if a["version"]:
                versions[a["version"]] = versions.get(a["version"], 0) + 1
        audit.record(db, user.username, "parc.view", "tenant", tenant.key, tenant.id, {"agents": len(agents)})
        commit(db)
        out = {
            "client": {"key": tenant.key, "name": tenant.name},
            "clients": [{"key": t.key, "name": t.name} for t in sorted(user.tenants, key=lambda t: t.key)],
            "configured": wa.api_configured(tenant), "manager_version": tenant.wazuh_manager_version,
            "polled_at": rfc3339(tenant.wazuh_agents_polled_at), "poll_interval_s": settings.wazuh_agents_poll_s,
            "events_known": events_known, "agents": agents,
            "versions": [{"version": v, "count": n, "gap": wa.version_gap(v, tenant.wazuh_manager_version)}
                         for v, n in sorted(versions.items(), key=lambda x: wa.version_tuple(x[0]) or (0, 0, 0), reverse=True)],
        }
        # Le client sait que le relevé est en échec, l'équipe sait pourquoi.
        out["error"] = tenant.wazuh_agents_error if team else (bool(tenant.wazuh_agents_error) or None)
        return out

    @app.get("/api/v1/parc/{client}/agents/{agent_id}")
    def agent_detail(client: str, agent_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        tenant = tenant_for(user, client)
        team = user.role in ("analyst", "manager")
        a = db.scalars(select(WazuhAgent).where(WazuhAgent.tenant_id == tenant.id, WazuhAgent.agent_id == agent_id[:16])).first()
        if a is None:
            raise HTTPException(404, "Agent inconnu.")
        now = utcnow()
        events = db.scalars(select(WazuhAgentEvent).where(WazuhAgentEvent.tenant_id == tenant.id,
                                                          WazuhAgentEvent.agent_id == a.agent_id)
                            .order_by(WazuhAgentEvent.at)).all()
        week = wa.timeline(events, now - timedelta(days=7), now)
        month = wa.timeline(events, now - timedelta(days=30), now)
        span = 7 * 86400
        out = agent_view(a, tenant, now, team, importance_by_agent(db, tenant),
                         open_tickets(db, tenant) if team else {}, wz.context_configured(tenant))
        out.update({
            "availability_7d": wa.availability(week), "availability_30d": wa.availability(month),
            "timeline_7d": [{"status": s["status"], "share": round((s["end"] - s["start"]).total_seconds() / span, 4)} for s in week],
            "changes": [{"at": rfc3339(e.at), "status": e.status, "previous": e.previous} for e in reversed(events[-30:])],
        })
        if team:
            out["tickets"] = [t for t, in db.execute(select(Ticket.ref).where(Ticket.tenant_id == tenant.id,
                              Ticket.agent_id == a.agent_id, Ticket.status.in_(OPEN)).order_by(Ticket.created_at.desc()))]
        audit.record(db, user.username, "parc.agent_view", "tenant", tenant.key, tenant.id, {"agent": a.agent_id})
        commit(db)
        return out

    @app.post("/api/v1/parc/{client}/refresh")
    def refresh(client: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        team_only(user)
        tenant = tenant_for(user, client)
        if not wa.api_configured(tenant):
            raise HTTPException(409, "L'accès à l'API Wazuh n'est pas configuré pour ce client (Administration, Clients).")
        if not refresh_limiter.allow(tenant.key, db):
            raise HTTPException(429, "Un relevé vient d'être demandé pour ce client : réessayer dans une minute.")
        lock = tenant_lock(tenant.id)
        if not lock.acquire(timeout=40):
            raise HTTPException(409, "Un relevé est déjà en cours pour ce client.")
        try:
            result = refresh_tenant(db, settings, box, tenant)
            audit.record(db, user.username, "parc.refresh", "tenant", tenant.key, tenant.id,
                         {k: v for k, v in result.items() if k != "erreur"} | ({"echec": True} if "erreur" in result else {}))
            commit(db)
        finally:
            lock.release()
        if "erreur" in result:
            raise HTTPException(502, result["erreur"])
        return result

    @app.get("/api/v1/parc/{client}/export.csv")
    def export(client: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        team_only(user)
        tenant = tenant_for(user, client)
        now = utcnow()
        imp, tickets = importance_by_agent(db, tenant), open_tickets(db, tenant)
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";")
        w.writerow(["agent", "nom", "adresse", "systeme", "version", "ecart_version", "etat", "depuis", "dernier_contact",
                    "dernier_evenement", "importance", "groupes", "tickets_ouverts"])
        safe = lambda v: ("'" + v) if isinstance(v, str) and v[:1] in "=+-@\t\r" else v  # noqa: E731 - injection de formule
        rows = db.scalars(select(WazuhAgent).where(WazuhAgent.tenant_id == tenant.id).order_by(WazuhAgent.name)).all()
        for a in rows:
            f = wa.flags(a, tenant.wazuh_manager_version, now, wz.context_configured(tenant))
            w.writerow([safe(x) for x in (a.agent_id, a.name, a.ip or "", " ".join(x for x in (a.os_name, a.os_version) if x),
                        a.version or "", f["version_gap"] or "", a.status, rfc3339(a.status_since),
                        rfc3339(a.last_keepalive) or "", rfc3339(a.last_event_at) or "", imp.get(a.agent_id) or "",
                        ",".join(a.groups or []), tickets.get(a.agent_id, 0))])
        audit.record(db, user.username, "parc.export", "tenant", tenant.key, tenant.id, {"agents": len(rows)})
        commit(db)
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="parc-{tenant.key}.csv"'})

    @app.post("/api/v1/parc/{client}/agents/{agent_id}/ticket", status_code=201)
    def disconnected_ticket(client: str, agent_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Ticket « agent déconnecté », ouvert à la main par l'équipe (pas de ticket automatique : décision du
        mainteneur, 24/11/2026). Il passe par l'ingestion ordinaire : dédoublonnage, notifications, audit."""
        team_only(user)
        tenant = tenant_for(user, client)
        a = db.scalars(select(WazuhAgent).where(WazuhAgent.tenant_id == tenant.id, WazuhAgent.agent_id == agent_id[:16])).first()
        if a is None:
            raise HTTPException(404, "Agent inconnu.")
        if a.status != "disconnected":
            raise HTTPException(409, "Cet agent n'est pas déconnecté.")
        since = as_utc(a.status_since)
        alert = {
            "id": f"keryx-parc-{a.agent_id}-{int(since.timestamp())}",
            "timestamp": since.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {"id": "keryx-agent-deconnecte", "level": 10, "groups": ["keryx_parc"],
                     "description": "Agent Wazuh déconnecté : plus de contact avec le manager"},
            "agent": {"id": a.agent_id, "name": a.name, "ip": a.ip or "",
                      "labels": {"importance": importance_by_agent(db, tenant).get(a.agent_id) or "standard"}},
            "location": "keryx/parc", "decoder": {"name": "keryx"},
            "full_log": f"Dernier contact avec le manager : {rfc3339(a.last_keepalive) or 'inconnu'} ; "
                        f"déconnecté depuis {rfc3339(a.status_since)} (relevé de l'API Wazuh par Keryx).",
        }
        try:
            result = ingest_alert(db, settings, tenant, alert, user.username)
        except AlertRejected as exc:
            db.rollback()
            raise HTTPException(422, str(exc)) from None
        audit.record(db, user.username, "parc.ticket", "tenant", tenant.key, tenant.id,
                     {"agent": a.agent_id, "ticket": result.ticket.ref if result.ticket else None, "resultat": result.status})
        commit(db)
        return {"ref": result.ticket.ref if result.ticket else None, "status": result.status}
