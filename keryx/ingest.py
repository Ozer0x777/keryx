"""Ingestion d'une alerte Wazuh → ticket pré-rempli (ou rattachement à un ticket ouvert).

[PDIS IV.2.1.w] contenu minimal du ticket ; [IV.2.1.aa] contexte rattaché ;
[IV.2.1.bb] registre chronologique par client ; [IV.2.3.g, h] notification minimale enregistrée.
L'alerte est une donnée non fiable : chaque champ est typé, borné et échappé.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DbSession

from . import astreinte, audit
from .config import Settings
from .ids import as_utc, parse_wazuh_timestamp, utcnow
from .mitre import enrich
from .models import Notification, RawAlert, Tenant, Ticket, TicketEvent, tlp_initial
from .notify import queue_new_ticket
from .sanitize import clean_html, esc
from .severity import criticite_initiale, importance_from_alert

COMPLIANCE_KEYS = ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13")
USEFUL_DATA_KEYS = ("srcip", "srcport", "dstip", "dstport", "srcuser", "dstuser", "protocol", "url", "status")


class AlertRejected(ValueError):
    pass


@dataclass
class IngestResult:
    status: str            # created | merged | ignored
    ticket: Ticket | None
    reason: str | None = None
    notifications: list[Notification] = field(default_factory=list)


# ---------------------------------------------------------------- lecture défensive
# Caractères de contrôle retirés de toute valeur lue dans l'alerte (sauf tabulation et fins de ligne) : PostgreSQL
# refuse le caractère nul dans un texte, et une alerte qui le contient ferait échouer l'ingestion, donc perdre le
# ticket (trouvé par fuzz/fuzz_alerte_wazuh.py). L'alerte brute conservée garde l'original, échappé par JSON.
# Sont aussi retirés : les contrôles C1, les caractères qui inversent ou isolent le sens d'écriture (un titre pourrait
# s'afficher autrement qu'il ne se lit, à la manière de « Trojan Source ») et les demi-codets isolés (`\ud800`, accepté
# par JSON mais ni encodable en UTF-8 ni enregistrable).
_CONTROLES = dict.fromkeys([*range(0, 9), 11, 12, *range(14, 32), *range(0x7F, 0xA0), *range(0x202A, 0x202F),
                            *range(0x2066, 0x206A), *range(0xD800, 0xE000)])
_UNE_LIGNE = {9: " ", 10: " ", 13: " "}
_PROFONDEUR_MAX = 32


def _sans_controle(v, profondeur: int = 0):
    """Valeurs nettoyées ; les clés ne le sont pas (deux clés pourraient sinon fusionner, « src\x00ip » écrasant
    « srcip ») : une clé abîmée ne correspond simplement à aucun champ lu par Keryx."""
    if isinstance(v, str):
        return v.translate(_CONTROLES)
    if profondeur >= _PROFONDEUR_MAX:
        return None  # au-delà, rien n'est lu par Keryx (l'original reste dans l'alerte brute)
    if isinstance(v, dict):
        return {k: _sans_controle(x, profondeur + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_sans_controle(x, profondeur + 1) for x in v]
    return v


def _dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _str(v, limit: int, lignes: bool = False) -> str:
    """Texte d'un champ, borné ; sur une seule ligne sauf demande (journal brut)."""
    if v is None or isinstance(v, (dict, list)):
        return ""
    texte = str(v).translate(_CONTROLES)
    return (texte if lignes else texte.translate(_UNE_LIGNE))[:limit]


def _str_list(v, limit_items: int = 50, limit_len: int = 120) -> list[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    return [_str(x, limit_len) for x in v[:limit_items] if not isinstance(x, (dict, list))]


def _rule(alert: dict) -> dict:
    rule = alert.get("rule")
    if not isinstance(rule, dict) or "id" not in rule or "level" not in rule:
        raise AlertRejected("Alerte invalide : bloc rule.id / rule.level absent.")
    return rule


TITLE_MAX = 100  # longueur maximale de la partie « description » du titre


def short_title(description: str, agent_name: str) -> str:
    """Titre lisible dans la file : la description de la règle, espaces normalisés, coupée à TITLE_MAX caractères sur
    une limite de mot (une règle peut insérer une ligne de commande entière dans sa description, ex. Sysmon/PowerShell).
    La description complète reste dans le corps du ticket et dans `rule_description`."""
    text = " ".join(description.split())
    if len(text) > TITLE_MAX:
        cut = text[:TITLE_MAX]
        space = cut.rfind(" ")
        text = (cut[:space] if space >= TITLE_MAX * 0.6 else cut).rstrip(" ,;:-") + "…"
    agent = " ".join(agent_name.split())
    return f"{text} — {agent or 'agent inconnu'}"


def _classification(rule: dict) -> list[str]:
    out = [f"group:{g}" for g in _str_list(rule.get("groups"))]
    for key in COMPLIANCE_KEYS:
        for v in _str_list(rule.get(key)):
            out.append(f"{key}:{v}")
    return out


def build_body(alert: dict, rule: dict) -> str:
    agent = _dict(alert.get("agent"))
    data = _dict(alert.get("data"))
    rows = [
        ("Règle", f"{_str(rule.get('id'), 32)} — niveau {_str(rule.get('level'), 4)}"),
        ("Description", _str(rule.get("description"), 500)),
        ("Agent", f"{_str(agent.get('id'), 32)} · {_str(agent.get('name'), 200)} · {_str(agent.get('ip'), 64)}"),
        ("Horodatage Wazuh", _str(alert.get("timestamp"), 40)),
        ("Emplacement", _str(alert.get("location"), 300)),
        ("Décodeur", _str(_dict(alert.get("decoder")).get("name"), 100)),
        ("Identifiant d'alerte", _str(alert.get("id"), 64)),
    ]
    for k in USEFUL_DATA_KEYS:
        if k in data:
            rows.append((f"data.{k}", _str(data[k], 500)))
    table = "".join(f'<tr><th scope="row">{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in rows)
    body = (
        f"<p>Alerte Wazuh reçue : <strong>{esc(_str(rule.get('description'), 500).rstrip('.'))}</strong>.</p>"
        f"<table><tbody>{table}</tbody></table>"
    )
    full_log = _str(alert.get("full_log"), 20_000, lignes=True)
    if full_log:
        body += f"<h3>Journal brut</h3><pre><code>{esc(full_log)}</code></pre>"
    return clean_html(body)


def next_ref(db: DbSession, tenant: Tenant) -> tuple[int, str]:
    """Incrément atomique en base (UPDATE … RETURNING) : pas de doublon sous charge concurrente."""
    seq = db.execute(
        update(Tenant).where(Tenant.id == tenant.id).values(next_seq=Tenant.next_seq + 1).returning(Tenant.next_seq)
    ).scalar_one() - 1
    return seq, f"{tenant.key}-{seq}"


# ---------------------------------------------------------------- ingestion
MAX_RAW_PER_TICKET = 500
_CRIT_RANK = {"Faible": 1, "Moyenne": 2, "Élevée": 3, "Critique": 4}


def ingest_alert(db: DbSession, settings: Settings, tenant: Tenant, alert: dict, actor: str) -> IngestResult:
    if not isinstance(alert, dict):
        raise AlertRejected("Le corps doit être un objet JSON.")
    original, alert = alert, _sans_controle(alert)
    rule = _rule(alert)
    try:
        level = int(rule["level"])
    except (TypeError, ValueError, OverflowError) as exc:
        raise AlertRejected("rule.level doit être un entier.") from exc
    if not 0 <= level <= 16:
        raise AlertRejected("rule.level doit être compris entre 0 et 16.")

    crit = criticite_initiale(level, settings.min_rule_level)
    if crit is None:
        return IngestResult("ignored", None, f"niveau {level} sous le seuil {settings.min_rule_level}")

    agent = _dict(alert.get("agent"))
    rule_id = _str(rule.get("id"), 32)
    if not rule_id:
        raise AlertRejected("rule.id vide.")
    agent_id = _str(agent.get("id"), 32)
    detected = parse_wazuh_timestamp(_str(alert.get("timestamp"), 40))
    now = utcnow()
    raw = json.dumps(original, ensure_ascii=False, sort_keys=True)
    try:
        raw_bytes = raw.encode("utf-8")
    except UnicodeEncodeError:
        # Demi-codet isolé dans l'alerte : l'original est gardé échappé (\ud800), seule forme enregistrable.
        raw = json.dumps(original, ensure_ascii=True, sort_keys=True)
        raw_bytes = raw.encode("ascii")
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    wazuh_id = _str(alert.get("id"), 64) or None

    # Sérialise l'ingestion par client (PostgreSQL : verrou de ligne ; SQLite : sans effet, déjà sérialisé) :
    # deux alertes simultanées de même règle et même agent ne créent plus deux tickets.
    db.execute(select(Tenant.id).where(Tenant.id == tenant.id).with_for_update())

    # Idempotence : une alerte déjà reçue (même identifiant Wazuh) n'est pas comptée deux fois
    # (le script Wazuh réessaie après un délai dépassé).
    if wazuh_id:
        dup = db.scalars(select(RawAlert).where(RawAlert.tenant_id == tenant.id,
                                                RawAlert.wazuh_id == wazuh_id).limit(1)).first()
        if dup:
            return IngestResult("duplicate", db.get(Ticket, dup.ticket_id))

    # Dédoublonnage : même client, même règle, même agent, ticket encore ouvert, vu récemment.
    window_start = now - timedelta(minutes=settings.dedup_minutes)
    candidates = db.scalars(
        select(Ticket).where(
            Ticket.tenant_id == tenant.id,
            Ticket.rule_id == rule_id,
            Ticket.agent_id == agent_id,
            Ticket.status.in_(("nouveau", "en_evaluation", "en_reponse")),
        ).order_by(Ticket.last_seen_at.desc())
    ).all()
    existing = next((t for t in candidates if as_utc(t.last_seen_at) >= window_start), None)

    if existing:
        existing.occurrences += 1
        existing.last_seen_at = now
        existing.updated_at = now
        if _CRIT_RANK[crit] > _CRIT_RANK.get(existing.criticite_initiale, 0):
            existing.criticite_initiale = crit  # la criticité ne redescend jamais lors d'une fusion
            existing.rule_level = level
        kept = db.scalar(select(func.count()).select_from(RawAlert).where(RawAlert.ticket_id == existing.id))
        # Plafond de stockage : au-delà, seule l'empreinte de l'alerte est conservée.
        payload = raw if kept < MAX_RAW_PER_TICKET else json.dumps({"non_conserve": "plafond atteint", "sha256": raw_hash})
        db.add(RawAlert(ticket_id=existing.id, tenant_id=tenant.id, wazuh_id=wazuh_id, sha256=raw_hash, payload=payload))
        db.add(TicketEvent(ticket_id=existing.id, actor=actor, action="occurrence",
                           details={"occurrences": existing.occurrences, "wazuh_id": wazuh_id}))
        audit.record(db, actor, "ticket.merge_alert", "ticket", existing.ref, tenant.id,
                     {"occurrences": existing.occurrences, "alert_sha256": raw_hash})
        return IngestResult("merged", existing)

    mitre, mitre_source = enrich(db, rule)
    seq, ref = next_ref(db, tenant)
    description = _str(rule.get("description"), 500) or "Alerte Wazuh"
    title = short_title(description, _str(agent.get("name"), 200))
    agent_ip = _str(agent.get("ip"), 64) or None
    ticket = Ticket(
        tenant_id=tenant.id, seq=seq, ref=ref, title=title, tlp=tlp_initial(tenant.tlp_plancher),
        body_html=build_body(alert, rule), status="nouveau",
        criticite_initiale=crit, importance=importance_from_alert(alert),
        rule_id=rule_id, rule_level=level, rule_description=description,
        rule_groups=_str_list(rule.get("groups")),
        agent_id=agent_id, agent_name=_str(agent.get("name"), 200), agent_ip=agent_ip,
        mitre=mitre, mitre_source=mitre_source, classification=_classification(rule),
        occurrences=1, detected_at=detected, last_seen_at=now, created_at=now, updated_at=now,
    )
    db.add(ticket)
    db.flush()
    db.add(RawAlert(ticket_id=ticket.id, tenant_id=tenant.id, wazuh_id=wazuh_id, sha256=raw_hash, payload=raw))
    db.add(TicketEvent(ticket_id=ticket.id, actor=actor, action="creation", visible_client=True,
                       details={"rule_id": rule_id, "rule_level": level, "criticite_initiale": crit,
                                "mitre_source": mitre_source}))
    notifications = queue_new_ticket(db, settings, tenant, ticket)
    notifications += astreinte.queue_new_ticket(db, settings, tenant, ticket, actor)   # équipe (ADR-0032)
    audit.record(db, actor, "ticket.create", "ticket", ref, tenant.id,
                 {"rule_id": rule_id, "level": level, "alert_sha256": raw_hash})
    return IngestResult("created", ticket, notifications=notifications)
