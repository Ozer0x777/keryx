"""Identifiants et horodatage.

- UUIDv7 : RFC 9562 §5.7 (non devinables, triables par date).
- Dates : toujours en UTC, sérialisées au format RFC 3339 (profil d'ISO 8601).
  ISO/IEC 27002:2022 8.17 : horodatage fiable (serveurs synchronisés NTP/NTS, RFC 5905 / 8915).
"""
from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone


def uuid7() -> str:
    """UUID version 7 (RFC 9562) : 48 bits d'horodatage ms + 74 bits aléatoires."""
    ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = int.from_bytes(os.urandom(10), "big")  # 80 bits
    rand_a = (rand >> 62) & 0xFFF                   # 12 bits
    rand_b = rand & ((1 << 62) - 1)                 # 62 bits
    value = (ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return str(uuid.UUID(int=value))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite renvoie des dates sans fuseau : on les relit comme UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def rfc3339(dt: datetime | None) -> str | None:
    dt = as_utc(dt)
    if dt is None:
        return None
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp_strict(value: str | None) -> datetime | None:
    """Date ISO 8601 / RFC 3339 (dont le format Wazuh « 2026-11-20T14:12:07.412+0000 ») en UTC, ou None si illisible.
    Aucune valeur de repli : à utiliser quand une date inventée fausserait une chronologie."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    # +0000 -> +00:00
    if len(v) > 5 and v[-5] in "+-" and v[-4:].isdigit():
        v = v[:-2] + ":" + v[-2:]
    try:
        parsed = datetime.fromisoformat(v)
    except ValueError:
        return None
    return as_utc(parsed)


def parse_wazuh_timestamp(value: str | None) -> datetime:
    """Wazuh envoie par ex. 2026-11-20T14:12:07.412+0000. Date illisible ou absente : heure de réception."""
    return parse_timestamp_strict(value) or utcnow()
