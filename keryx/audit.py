"""Journal d'audit chaîné (HMAC-SHA256) + points de contrôle + export syslog RFC 5424.

[PDIS IV.3.9.c] tous les accès et actions sont journalisés.
[ISO/IEC 27002:2022 8.15] protection des journaux :
- chaque entrée est scellée par un HMAC qui inclut le sceau de la précédente ; la clé est
  dérivée de KERYX_SECRET_KEY et n'est pas dans la base : réécrire la chaîne exige la clé ;
- la troncature (suppression des dernières entrées) se détecte en comparant à un point de
  contrôle conservé hors de Keryx (syslog vers Wazuh, ou `keryx checkpoint` archivé).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import socket
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .db import serialize_writes
from .ids import rfc3339, utcnow
from .models import AuditEntry

GENESIS = "0" * 64
AUDIT_LOCK_ID = 0x6B65727978  # « keryx »


class _Key:
    value: bytes | None = None


_KEY = _Key()


def configure(secret_key_b64: str) -> None:
    """Dérive la clé de scellement du journal à partir de la clé maîtresse (séparation des usages)."""
    import base64
    master = base64.b64decode(secret_key_b64)
    _KEY.value = hmac.new(master, b"keryx-audit-chain-v1", hashlib.sha256).digest()


def _neutralize(value: str) -> str:
    """Remplace tout caractère de contrôle (retour ligne inclus) : empêche l'injection de lignes."""
    return "".join(c if (c >= " " and c != "\x7f") else f"\\x{ord(c):02x}" for c in value)


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _seal(prev_hash: str, payload: dict[str, Any]) -> str:
    if _KEY.value is None:
        raise RuntimeError("Journal d'audit non configuré (audit.configure).")
    return hmac.new(_KEY.value, (prev_hash + _canonical(payload)).encode("utf-8"), hashlib.sha256).hexdigest()


def _payload(seq: int, entry_ts: str, actor: str, action: str, object_type, object_id, tenant_id, details) -> dict:
    return {
        "seq": seq, "ts": entry_ts, "actor": actor, "action": action, "object_type": object_type,
        "object_id": object_id, "tenant_id": tenant_id, "details": details or {},
    }


def record(
    db: DbSession,
    actor: str,
    action: str,
    object_type: str | None = None,
    object_id: str | None = None,
    tenant_id: str | None = None,
    details: dict | None = None,
) -> AuditEntry:
    # Sérialise l'ajout : deux transactions ne doivent jamais chaîner sur la même entrée.
    serialize_writes(db, AUDIT_LOCK_ID)
    last = db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).first()
    prev = last.hash if last else GENESIS
    seq = (last.seq + 1) if last else 1
    ts = rfc3339(utcnow())
    actor = actor[:120]
    payload = _payload(seq, ts, actor, action, object_type, object_id, tenant_id, details)
    entry = AuditEntry(
        seq=seq, ts=ts, actor=actor, action=action, object_type=object_type, object_id=object_id,
        tenant_id=tenant_id, details=details or {}, prev_hash=prev, hash=_seal(prev, payload),
    )
    db.add(entry)
    db.flush()
    db.info.setdefault("audit_new", []).append(entry)  # export syslog après commit
    return entry


def verify_chain(db: DbSession, checkpoint: tuple[int, str] | None = None) -> tuple[bool, int | None]:
    """Recalcule toute la chaîne. Avec un point de contrôle (seq, sceau) conservé à l'extérieur,
    détecte aussi la suppression des dernières entrées. Renvoie (ok, première entrée en défaut)."""
    prev, expected_seq, seen = GENESIS, 1, {}
    for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq)):
        payload = _payload(e.seq, e.ts, e.actor, e.action, e.object_type, e.object_id, e.tenant_id, e.details)
        if e.seq != expected_seq or e.prev_hash != prev or not hmac.compare_digest(e.hash, _seal(prev, payload)):
            return False, e.seq
        seen[e.seq] = e.hash
        prev, expected_seq = e.hash, e.seq + 1
    if checkpoint is not None:
        seq, seal = checkpoint
        if seen.get(seq) != seal:
            return False, seq
    return True, None


def head(db: DbSession) -> tuple[int, str]:
    last = db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).first()
    return (last.seq, last.hash) if last else (0, GENESIS)


def to_syslog(entry: AuditEntry, hostname: str, app: str = "keryx") -> str:
    """Formate une entrée au format RFC 5424.
    PRI = facility 13 (log audit) * 8 + severity 6 (informational) = 110."""
    def sd_escape(v: str) -> str:
        v = v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
        return _neutralize(v)

    sd = (
        f'[keryx@32473 seq="{entry.seq}" actor="{sd_escape(entry.actor)}" '
        f'action="{sd_escape(entry.action)}" object="{sd_escape(entry.object_id or "-")}" '
        f'hash="{entry.hash}"]'
    )
    msg = _canonical(entry.details or {})  # json.dumps échappe déjà les caractères de contrôle
    return f"<110>1 {entry.ts} {_neutralize(hostname)} {app} - AUDIT {sd} {msg}"


def send_syslog(line: str, host: str, port: int) -> None:  # pragma: no cover - réseau
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(line.encode("utf-8"), (host, port))
