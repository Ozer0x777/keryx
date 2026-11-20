"""Enrichissement MITRE ATT&CK en cascade.

1. Wazuh (rule.mitre) → source « wazuh »
2. Table de correspondance Keryx (rule.id, puis rule.groups) → source « table »
3. Sinon vide, source « a_completer » (l'analyste complète : source « manuel »)
Aucune déduction par mots-clés ni par IA.
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .models import MitreMapping

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def valid_technique(tid: str) -> bool:
    return bool(TECHNIQUE_RE.match(tid or ""))


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def from_wazuh(rule: dict) -> list[dict]:
    m = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    ids = _as_list(m.get("id"))
    tactics = _as_list(m.get("tactic"))
    techniques = _as_list(m.get("technique"))
    out = []
    for i, tid in enumerate(ids):
        tid = str(tid)
        if not valid_technique(tid):
            continue
        out.append({
            "id": tid,
            "technique": str(techniques[i]) if i < len(techniques) else "",
            "tactics": [str(t) for t in tactics],
        })
    return out


def from_table(db: DbSession, rule_id: str, groups: list[str]) -> list[dict]:
    rows = db.scalars(select(MitreMapping).where(MitreMapping.rule_id == rule_id)).all()
    if not rows and groups:
        rows = db.scalars(select(MitreMapping).where(MitreMapping.rule_group.in_(groups))).all()
    out, seen = [], set()
    for r in rows:
        if r.technique_id in seen:
            continue
        seen.add(r.technique_id)
        out.append({"id": r.technique_id, "technique": r.technique_name, "tactics": [r.tactic] if r.tactic else []})
    return out


def enrich(db: DbSession, rule: dict) -> tuple[list[dict], str]:
    found = from_wazuh(rule)
    if found:
        return found, "wazuh"
    groups = [str(g)[:120] for g in _as_list(rule.get("groups")) if not isinstance(g, (dict, list))]
    found = from_table(db, str(rule.get("id", "")), groups)
    if found:
        return found, "table"
    return [], "a_completer"
