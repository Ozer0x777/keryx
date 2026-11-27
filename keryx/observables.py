"""Éléments relevés dans les alertes Wazuh d'un ticket (adresses IP, noms d'hôte, comptes, empreintes, domaines).

Ils servent à chercher un ticket par une valeur précise (`ip:185.220.101.4`, `compte:admin`…) et à proposer des
tickets « peut-être liés » qui partagent une valeur. Le relevé est fait à la réception de chaque alerte, y compris
quand l'alerte brute n'est plus conservée (plafond par ticket) ; il suit le ticket (fusion, rétention, export,
destruction). Rien ne sort de Keryx. Les valeurs sont des données non fiables : bornées en taille et en nombre,
jamais interprétées.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from .models import Observable

KINDS = ("ip", "hote", "compte", "hash", "domaine")
MAX_PAR_ALERTE = 200          # éléments retenus par alerte
MAX_VALEUR = 255
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HEX = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_HOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_DOMAINE = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
# Noms de champs (dernier segment, en minuscules) qui désignent un compte, un hôte, un domaine ou une empreinte.
CHAMPS_COMPTE = {"user", "dstuser", "srcuser", "username", "user_name", "account", "account_name", "login",
                 "targetusername", "subjectusername", "targetuser", "sourceuser"}
CHAMPS_HOTE = {"hostname", "host", "computer", "workstationname", "dhost", "shost", "srchost", "dsthost"}
CHAMPS_DOMAINE = {"domain", "dns_query", "queryname", "query", "url", "uri", "referer", "fqdn"}
INDICES_HASH = ("md5", "sha1", "sha256", "hash", "checksum")
VIDES = {"", "-", "n/a", "none", "null", "unknown"}


def normaliser(kind: str, value: str) -> str | None:
    """Forme canonique d'une valeur saisie ou relevée, ou None si elle n'est pas du bon type."""
    v = (value or "").strip().strip('"\'').strip()
    if not v or len(v) > MAX_VALEUR or v.lower() in VIDES:
        return None
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None
        return None if ip.is_unspecified else ip.compressed
    if kind == "hash":
        return v.lower() if _HEX.match(v) else None
    if kind == "hote":
        return v.lower() if _HOTE.match(v) else None
    if kind == "domaine":
        if "://" in v:
            v = urlsplit(v).hostname or ""
        v = v.lower().rstrip(".")
        return v if _DOMAINE.match(v) else None
    if kind == "compte":
        return v.lower() if all(c.isprintable() for c in v) else None
    return None


def extraire(alert: dict) -> set[tuple[str, str]]:
    """Éléments d'une alerte : IP partout (y compris le journal brut), le reste d'après le nom du champ."""
    out: set[tuple[str, str]] = set()

    def ajouter(kind: str, value) -> None:
        if len(out) < MAX_PAR_ALERTE:
            n = normaliser(kind, str(value))
            if n:
                out.add((kind, n))

    def parcourir(obj, cle: str, profondeur: int) -> None:
        if profondeur > 12 or len(out) >= MAX_PAR_ALERTE:
            return
        if isinstance(obj, dict):
            for k, v in list(obj.items())[:300]:
                parcourir(v, str(k), profondeur + 1)
            return
        if isinstance(obj, list):
            for v in obj[:200]:
                parcourir(v, cle, profondeur + 1)
            return
        if not isinstance(obj, (str, int)) or isinstance(obj, bool):
            return
        texte = str(obj)[:8192]
        nom = cle.rsplit(".", 1)[-1].lower()
        for m in _IPV4.finditer(texte):
            ajouter("ip", m.group(0))
        if ":" in texte and "ip" in nom:
            ajouter("ip", texte)                      # IPv6 dans un champ d'adresse
        if nom in CHAMPS_COMPTE:
            ajouter("compte", texte)
        if nom in CHAMPS_HOTE:
            ajouter("hote", texte)
        if nom in CHAMPS_DOMAINE:
            ajouter("domaine", texte)
        if any(i in nom for i in INDICES_HASH):
            ajouter("hash", texte)

    parcourir(alert, "", 0)
    agent = alert.get("agent") if isinstance(alert, dict) else None
    if isinstance(agent, dict) and agent.get("name"):
        ajouter("hote", agent["name"])
    return out


def enregistrer(db: DbSession, ticket_id: str, tenant_id: str, alert: dict) -> None:
    """Ajoute au ticket les éléments de l'alerte qu'il n'a pas déjà."""
    trouves = extraire(alert)
    if not trouves:
        return
    deja = set(db.execute(select(Observable.kind, Observable.value).where(Observable.ticket_id == ticket_id)).all())
    for kind, value in sorted(trouves - deja):
        db.add(Observable(ticket_id=ticket_id, tenant_id=tenant_id, kind=kind, value=value))


def deplacer(db: DbSession, src_id: str, dst_id: str) -> None:
    """Fusion : les éléments du ticket absorbé rejoignent le ticket conservé, sans doublon."""
    deja = set(db.execute(select(Observable.kind, Observable.value).where(Observable.ticket_id == dst_id)).all())
    for o in db.scalars(select(Observable).where(Observable.ticket_id == src_id)).all():
        if (o.kind, o.value) in deja:
            db.delete(o)
        else:
            o.ticket_id = dst_id
            deja.add((o.kind, o.value))


def effacer(db: DbSession, ticket_ids: list[str]) -> int:
    """Rétention : les éléments suivent les alertes brutes purgées."""
    if not ticket_ids:
        return 0
    return db.execute(delete(Observable).where(Observable.ticket_id.in_(ticket_ids))
                      .execution_options(synchronize_session=False)).rowcount or 0
