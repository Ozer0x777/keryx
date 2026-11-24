"""Parc d'agents Wazuh (ADR-0030) : relevé, en lecture seule, de l'état des agents d'un client dans l'API du manager
Wazuh, et du dernier événement de chaque agent dans l'indexeur.

Keryx n'agit jamais sur Wazuh : il s'authentifie, lit `/` (version du manager) et `/agents`, et c'est tout. La connexion
passe par le même connecteur que le contexte Wazuh (wazuh_context._connect) : adresse résolue et contrôlée par Keryx
(boucle locale, lien local et services de métadonnées refusés), TLS 1.2 au moins, certificat vérifié contre l'autorité
du client, aucune redirection suivie, réponse bornée.

Ce qui est écrit ici d'après la documentation de l'API Wazuh 4.x et vérifié contre le faux manager des tests
(tests/fake_wazuh_api.py) seulement : à valider contre un vrai manager (noms de champs, permissions du compte).
"""
from __future__ import annotations

import base64
import http.client
import json
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from . import wazuh_context as wz
from .ids import as_utc, utcnow
from .models import Tenant, WazuhAgent, WazuhAgentEvent

log = logging.getLogger("keryx.parc")

STATUSES = ("active", "disconnected", "never_connected", "pending")
PAGE = 500                    # agents par page de l'API
MAX_AGENTS = 20_000           # au-delà, le relevé s'arrête (protection mémoire) et le signale
TOTAL_TIMEOUT_S = 30.0        # pour tout un relevé : authentification, version, pages d'agents
DOWN_ALERT = timedelta(hours=24)       # « hors ligne depuis plus de 24 h »
SILENT_AFTER = timedelta(hours=24)     # actif, mais aucun événement indexé depuis 24 h
EVENT_WINDOW = "now-30d"               # fenêtre de recherche du dernier événement dans l'indexeur
SELECT = "id,name,ip,status,version,os.name,os.version,group,node_name,lastKeepAlive,dateAdd"
_GROUP = re.compile(r"^[A-Za-z0-9._-]{1,128}$")      # noms de groupes Wazuh
_AGENT_ID = re.compile(r"^[0-9]{3,8}$")
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


class ApiError(Exception):
    def __init__(self, message: str, reason: str):
        super().__init__(message)
        self.message, self.reason = message, reason


def validate_group(value: str) -> str:
    v = value.strip()
    if not _GROUP.match(v):
        raise wz.ConfigError("Groupe Wazuh invalide : lettres, chiffres, point, tiret et souligné, 128 caractères au plus.")
    return v


def api_configured(t: Tenant) -> bool:
    return bool(t.wazuh_api_url and t.wazuh_api_user and t.wazuh_api_password)


@dataclass
class ApiConfig:
    endpoint: wz.Endpoint
    username: str = field(repr=False)
    password: str = field(repr=False)
    tls_verify: bool = True
    ca_pem: str | None = field(default=None, repr=False)
    group: str | None = None
    allow_loopback: bool = False
    # Groupes des AUTRES clients du même manager : un agent qui en porte un est écarté, même s'il est aussi dans le
    # groupe de ce client (un agent Wazuh peut appartenir à plusieurs groupes) [PDIS IV.3.8.g].
    excluded_groups: tuple = ()

    def as_indexer(self) -> wz.IndexerConfig:
        """Le connecteur de wazuh_context ne lit que l'adresse et la confiance TLS."""
        return wz.IndexerConfig(endpoint=self.endpoint, username="", password="", tls_verify=self.tls_verify,
                                ca_pem=self.ca_pem, allow_loopback=self.allow_loopback)


def _api_message(exc: wz.IndexerError) -> ApiError:
    text = exc.message.replace("L'indexeur Wazuh", "L'API du manager Wazuh").replace("l'indexeur Wazuh", "l'API du manager Wazuh")
    return ApiError(text, exc.reason)


def _exchange(sock: ssl.SSLSocket, endpoint: wz.Endpoint, method: str, path: str, headers: dict, payload: bytes | None,
              deadline: float) -> tuple[int, bytes, bool]:
    """Une requête HTTP/1.1 écrite à la main sur la connexion contrôlée (aucune redirection, aucun mandataire)."""
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    if endpoint.port != 443:
        host += f":{endpoint.port}"
    body = payload or b""
    lines = [f"{method} {endpoint.base_path}{path} HTTP/1.1", f"Host: {host}", "Accept: application/json",
             "Accept-Encoding: identity", "User-Agent: keryx", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    sock.settimeout(max(0.1, deadline - time.monotonic()))
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
    resp = http.client.HTTPResponse(sock, method=method)
    try:
        resp.begin()
        if 300 <= resp.status < 400:
            raise ApiError("L'API du manager Wazuh a répondu par une redirection : Keryx ne la suit pas "
                           "(vérifier l'adresse configurée).", "redirection")
        data = wz._read_bounded(sock, resp, deadline)
        return resp.status, data, not resp.will_close
    finally:
        resp.close()


def _json(data: bytes, what: str) -> dict:
    try:
        doc = json.loads(data)
        if not isinstance(doc, dict):
            raise TypeError
        return doc
    except (ValueError, TypeError, RecursionError) as exc:
        raise ApiError(f"La réponse de l'API du manager Wazuh ({what}) n'est pas du JSON attendu.", "reponse_invalide") from exc


def version_of(value) -> str | None:
    """« Wazuh v4.12.0 » ou « v4.12.0 » ou « 4.12.0 » vers « 4.12.0 » ; autre forme : None."""
    m = _VERSION.search(str(value or ""))
    return m.group(0) if m else None


def version_tuple(v: str | None) -> tuple[int, int, int] | None:
    m = _VERSION.fullmatch(v or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def version_gap(agent: str | None, manager: str | None) -> str | None:
    """None = à jour ou inconnue ; « retard » = plus ancienne que le manager ; « tres_ancienne » = autre version majeure
    ou au moins trois versions mineures d'écart ; « plus_recente » = plus récente que le manager (non prise en charge
    par Wazuh)."""
    a, m = version_tuple(agent), version_tuple(manager)
    if not a or not m or a == m:
        return None
    if a > m:
        return "plus_recente"
    if a[0] != m[0] or m[1] - a[1] >= 3:
        return "tres_ancienne"
    return "retard"


def _date(value) -> datetime | None:
    if not isinstance(value, str) or not value or value.startswith("9999"):
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _text(value, limit: int) -> str | None:
    v = wz.clean_text(value, limit) if value not in (None, "") else ""
    return v or None


def normalize(item: dict) -> dict | None:
    """Un agent de l'API, réduit aux champs gardés et nettoyé ; None si l'entrée est inexploitable."""
    if not isinstance(item, dict):
        return None
    agent_id = str(item.get("id", ""))
    if not _AGENT_ID.match(agent_id) or agent_id == "000":      # 000 : le manager lui-même, pas un agent du client
        return None
    status = item.get("status") if item.get("status") in STATUSES else None
    if status is None:
        return None
    os_ = item.get("os") if isinstance(item.get("os"), dict) else {}
    groups = item.get("group") if isinstance(item.get("group"), list) else []
    return {
        "agent_id": agent_id, "name": _text(item.get("name"), 200) or agent_id, "ip": _text(item.get("ip"), 64),
        "os_name": _text(os_.get("name"), 120), "os_version": _text(os_.get("version"), 120),
        "version": version_of(item.get("version")), "status": status,
        "groups": [g for g in (_text(x, 128) for x in groups[:20]) if g],
        "node": _text(item.get("node_name"), 120),
        "last_keepalive": _date(item.get("lastKeepAlive")), "registered_at": _date(item.get("dateAdd")),
    }


@dataclass
class Snapshot:
    manager_version: str | None
    agents: list[dict]
    truncated: bool = False


def fetch(cfg: ApiConfig) -> Snapshot:
    """Authentification, version du manager, puis tous les agents (par pages), sur une seule connexion si possible."""
    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    conn = {"sock": None}

    def call(method: str, path: str, headers: dict) -> tuple[int, bytes]:
        if conn["sock"] is None:
            conn["sock"] = wz._connect(cfg.as_indexer(), deadline)
        status, data, reusable = _exchange(conn["sock"], cfg.endpoint, method, path, headers, None, deadline)
        if not reusable:            # « Connection: close » : nouvelle connexion, contrôlée de même, pour la suite
            conn["sock"].close()
            conn["sock"] = None
        return status, data

    try:
        basic = base64.b64encode(f"{cfg.username}:{cfg.password}".encode("utf-8")).decode("ascii")
        status, data = call("POST", "/security/user/authenticate", {"Authorization": f"Basic {basic}"})
        if status in (401, 403):
            raise ApiError("L'API du manager Wazuh refuse le compte de lecture configuré (identifiants ou droits).", "authentification")
        if status != 200:
            raise ApiError(f"L'API du manager Wazuh a répondu par une erreur à l'authentification ({status}).", f"statut_{status}")
        token = (_json(data, "authentification").get("data") or {}).get("token")
        if not isinstance(token, str) or not token or len(token) > 8192 or any(c in token for c in "\r\n "):
            raise ApiError("L'API du manager Wazuh n'a pas renvoyé de jeton utilisable.", "jeton")
        bearer = {"Authorization": f"Bearer {token}"}
        status, data = call("GET", "/", bearer)
        manager = version_of((_json(data, "version").get("data") or {}).get("api_version")) if status == 200 else None
        agents, offset, truncated = {}, 0, False
        while True:
            query = {"limit": PAGE, "offset": offset, "select": SELECT, "sort": "+id"}
            if cfg.group:
                query["group"] = cfg.group
            status, data = call("GET", "/agents?" + urlencode(query, safe=",+"), bearer)
            if status in (401, 403):
                raise ApiError("Le compte de lecture n'a pas le droit de lister les agents (permission agent:read).", "droits")
            if status != 200:
                raise ApiError(f"L'API du manager Wazuh a répondu par une erreur à la liste des agents ({status}).", f"statut_{status}")
            payload = _json(data, "agents").get("data") or {}
            items = payload.get("affected_items")
            if not isinstance(items, list):
                raise ApiError("La réponse de l'API du manager Wazuh n'est pas une liste d'agents.", "reponse_invalide")
            for item in items:
                a = normalize(item)
                # Le filtre du serveur n'est pas cru sur parole : groupe du client exigé, groupes des autres clients refusés.
                if a and (not cfg.group or cfg.group in a["groups"]) and not set(a["groups"]) & set(cfg.excluded_groups):
                    agents[a["agent_id"]] = a        # un numéro vu deux fois (pagination décalée) n'est gardé qu'une fois
            total = payload.get("total_affected_items")
            offset += len(items)
            if not items or not isinstance(total, int) or offset >= total:
                break
            if offset >= MAX_AGENTS:
                truncated = True
                break
        return Snapshot(manager, list(agents.values()), truncated)
    except wz.IndexerError as exc:
        raise _api_message(exc) from exc
    except TimeoutError as exc:
        raise ApiError("L'API du manager Wazuh n'a pas répondu dans le délai imparti.", "delai") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise ApiError("La connexion à l'API du manager Wazuh a été interrompue.", "connexion") from exc
    finally:
        if conn["sock"] is not None:
            conn["sock"].close()


EVENT_BATCH = 5000


def last_events(cfg: wz.IndexerConfig, agent_ids: list[str]) -> dict[str, datetime]:
    """Date du dernier événement indexé (tous niveaux) par agent, sur les 30 derniers jours : une agrégation par lot de
    5 000 agents. Toute erreur (réseau, délai, réponse) lève wz.IndexerError : aucun résultat partiel."""
    out: dict[str, datetime] = {}
    for i in range(0, len(agent_ids), EVENT_BATCH):
        try:
            out.update(_last_events_batch(cfg, agent_ids[i:i + EVENT_BATCH]))
        except TimeoutError as exc:
            raise wz.IndexerError(503, "L'indexeur Wazuh n'a pas répondu dans le délai imparti.", "delai") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise wz.IndexerError(503, "La connexion à l'indexeur Wazuh a été interrompue.", "connexion") from exc
    return out


def _last_events_batch(cfg: wz.IndexerConfig, agent_ids: list[str]) -> dict[str, datetime]:
    if not agent_ids:
        return {}
    deadline = time.monotonic() + wz.TOTAL_TIMEOUT_S
    body = {"size": 0, "track_total_hits": False,
            "query": {"bool": {"filter": [{"terms": {"agent.id": agent_ids}},
                                          {"range": {cfg.time_field: {"gte": EVENT_WINDOW}}}]}},
            "aggs": {"agents": {"terms": {"field": "agent.id", "size": len(agent_ids)},
                                "aggs": {"last": {"max": {"field": cfg.time_field}}}}}}
    sock = wz._connect(cfg, deadline)
    try:
        basic = base64.b64encode(f"{cfg.username}:{cfg.password}".encode("utf-8")).decode("ascii")
        path = f"/{quote(cfg.index_pattern, safe='*._-')}/_search?ignore_unavailable=true&allow_no_indices=true"
        status, data, _ = _exchange(sock, cfg.endpoint, "POST", path,
                                    {"Authorization": f"Basic {basic}", "Content-Type": "application/json"},
                                    json.dumps(body).encode("utf-8"), deadline)
    except ApiError as exc:
        raise wz.IndexerError(502, exc.message.replace("l'API du manager Wazuh", "l'indexeur Wazuh").replace("L'API du manager Wazuh", "L'indexeur Wazuh"), exc.reason) from exc
    finally:
        sock.close()
    if status != 200:
        raise wz.IndexerError(502, f"L'indexeur Wazuh a répondu par une erreur ({status}).", f"statut_{status}")
    try:
        buckets = json.loads(data)["aggregations"]["agents"]["buckets"]
    except (ValueError, KeyError, TypeError) as exc:
        raise wz.IndexerError(502, "La réponse de l'indexeur Wazuh n'est pas une agrégation attendue.", "reponse_invalide") from exc
    wanted, out = set(agent_ids), {}
    for b in buckets if isinstance(buckets, list) else []:
        if not isinstance(b, dict) or str(b.get("key")) not in wanted:     # agent hors de la demande : écarté
            continue
        last = b.get("last") or {}
        when = _date(last.get("value_as_string")) if isinstance(last, dict) else None
        if when is None and isinstance(last, dict) and isinstance(last.get("value"), (int, float)):
            when = datetime.fromtimestamp(last["value"] / 1000, tz=timezone.utc)
        if when:
            out[str(b["key"])] = when
    return out


def _since(a: dict, now: datetime) -> datetime:
    """Depuis quand l'agent est dans son état, à la première observation : le dernier contact pour un agent
    déconnecté, l'enregistrement pour un agent jamais connecté, sinon maintenant."""
    if a["status"] == "disconnected" and a["last_keepalive"]:
        return min(a["last_keepalive"], now)
    if a["status"] in ("never_connected", "pending") and a["registered_at"]:
        return min(a["registered_at"], now)
    return now


def store(db: DbSession, tenant: Tenant, snap: Snapshot, events: dict[str, datetime] | None, now: datetime) -> dict:
    """Met à jour l'état des agents du client et ajoute à l'historique chaque changement d'état constaté."""
    current = {a.agent_id: a for a in db.scalars(select(WazuhAgent).where(WazuhAgent.tenant_id == tenant.id))}
    source = tenant.wazuh_api_url or ""
    seen, changes = set(), 0
    for a in snap.agents:
        seen.add(a["agent_id"])
        row = current.get(a["agent_id"])
        if row is None:
            since = _since(a, now)
            row = WazuhAgent(tenant_id=tenant.id, agent_id=a["agent_id"], status_since=since, status=a["status"])
            db.add(row)
            db.add(WazuhAgentEvent(tenant_id=tenant.id, agent_id=a["agent_id"], status=a["status"], previous=None, at=since,
                                   source=source))
            changes += 1
        elif row.status != a["status"]:
            since = now
            if a["status"] == "disconnected" and a["last_keepalive"] and as_utc(a["last_keepalive"]) > as_utc(row.status_since):
                since = min(a["last_keepalive"], now)      # la déconnexion date du dernier contact, pas du relevé
            db.add(WazuhAgentEvent(tenant_id=tenant.id, agent_id=a["agent_id"], status=a["status"], previous=row.status, at=since,
                                   source=source))
            row.status, row.status_since = a["status"], since
            changes += 1
        for k in ("name", "ip", "os_name", "os_version", "version", "groups", "node", "last_keepalive", "registered_at"):
            setattr(row, k, a[k])
        if events is not None:
            row.last_event_at = events.get(a["agent_id"])     # absent de l'indexeur sur 30 jours : aucun événement
        row.missed = 0
        row.updated_at = now
    # Un agent absent n'est déclaré retiré qu'au deuxième relevé consécutif sans lui : une pagination décalée par une
    # suppression pendant le relevé ne fait pas disparaître un agent bien présent.
    removed = []
    if not snap.truncated:
        for aid, row in current.items():
            if aid in seen:
                continue
            row.missed = (row.missed or 0) + 1
            if row.missed >= 2:
                removed.append(aid)
                db.add(WazuhAgentEvent(tenant_id=tenant.id, agent_id=aid, status="removed", previous=row.status, at=now,
                                       source=source))
        if removed:
            db.execute(delete(WazuhAgent).where(WazuhAgent.tenant_id == tenant.id, WazuhAgent.agent_id.in_(removed)))
    tenant.wazuh_manager_version = snap.manager_version
    tenant.wazuh_agents_polled_at = now
    tenant.wazuh_events_ok = events is not None
    tenant.wazuh_agents_error = "Relevé tronqué : plus de 20 000 agents." if snap.truncated else None
    return {"agents": len(snap.agents), "changements": changes, "retires": len(removed)}


# ---------------------------------------------------------------- calculs pour l'affichage

def timeline(events: list[WazuhAgentEvent], start: datetime, end: datetime) -> list[dict]:
    """Segments d'état entre `start` et `end` à partir de l'historique trié : [{status, start, end}], « inconnu » avant
    la première observation."""
    segs, state, cursor = [], "inconnu", start
    for e in events:
        at = as_utc(e.at)
        if at <= start:
            state = e.status
            continue
        if at >= end:
            break
        segs.append({"status": state, "start": cursor, "end": at})
        state, cursor = e.status, at
    segs.append({"status": state, "start": cursor, "end": end})
    merged = []
    for s in segs:
        if s["end"] <= s["start"]:
            continue
        if merged and merged[-1]["status"] == s["status"]:
            merged[-1]["end"] = s["end"]
        else:
            merged.append(dict(s))
    return merged


def availability(segs: list[dict]) -> float | None:
    """Part du temps observé passé actif. Ne comptent pas : le temps « inconnu » (avant la première observation), un
    agent retiré, et un agent jamais connecté ou en attente d'enregistrement (pas encore déployé : pas en panne).
    None si rien n'a été observé."""
    known = [s for s in segs if s["status"] in ("active", "disconnected")]
    total = sum((s["end"] - s["start"]).total_seconds() for s in known)
    if total <= 0:
        return None
    up = sum((s["end"] - s["start"]).total_seconds() for s in known if s["status"] == "active")
    return round(100 * up / total, 1)


def flags(a: WazuhAgent, manager_version: str | None, now: datetime, events_known: bool) -> dict:
    since = as_utc(a.status_since)
    gap = version_gap(a.version, manager_version)
    silent = None
    if events_known and a.status == "active":
        silent = a.last_event_at is None or now - as_utc(a.last_event_at) >= SILENT_AFTER
    return {"version_gap": gap, "outdated": gap in ("retard", "tres_ancienne"),
            "down24": a.status == "disconnected" and now - since >= DOWN_ALERT, "silent": silent}


def summary(db: DbSession, tenants: dict, start: datetime, end: datetime) -> dict | None:
    """Parc des clients du périmètre pour le pilotage et le rapport périodique : état courant et disponibilité
    moyenne sur la période (temps actif sur temps observé, agent par agent). None si aucun agent n'est relevé."""
    rows = db.scalars(select(WazuhAgent).where(WazuhAgent.tenant_id.in_(list(tenants)))).all()
    if not rows:
        return None
    now = utcnow()
    end = min(end, now)
    keys = {t_id: t.key for t_id, t in tenants.items()}
    history: dict[tuple, list] = {}
    for e in db.scalars(select(WazuhAgentEvent).where(WazuhAgentEvent.tenant_id.in_(list(tenants)), WazuhAgentEvent.at < end)
                        .order_by(WazuhAgentEvent.at)):
        if e.source == (tenants[e.tenant_id].wazuh_api_url or ""):       # historique du manager courant seulement
            history.setdefault((e.tenant_id, e.agent_id), []).append(e)
    per_agent, counts = [], {s: 0 for s in STATUSES}
    down24 = outdated = 0
    for a in rows:
        counts[a.status] = counts.get(a.status, 0) + 1
        f = flags(a, tenants[a.tenant_id].wazuh_manager_version, now, False)
        down24 += int(f["down24"])
        outdated += int(f["outdated"])
        av = availability(timeline(history.get((a.tenant_id, a.agent_id), []), start, end)) if end > start else None
        if av is not None:
            per_agent.append({"client": keys[a.tenant_id], "agent": a.agent_id, "name": a.name, "availability": av})
    per_agent.sort(key=lambda x: (x["availability"], x["name"]))
    return {"agents": len(rows), "by_status": counts, "down24": down24, "outdated": outdated,
            "availability_percent": round(sum(x["availability"] for x in per_agent) / len(per_agent), 1) if per_agent else None,
            "least_available": [x for x in per_agent if x["availability"] < 100][:5]}
