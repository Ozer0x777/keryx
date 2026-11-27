"""Recherche de tickets : texte libre ou champ précis (`ip:`, `hote:`, `agent:`, `regle:`, `compte:`, `hash:`,
`domaine:`, `ref:`), pour la file et pour la fenêtre « Lier à un autre ticket ».

Le texte libre couvre la référence, le titre, la règle, l'agent, la description et les commentaires ; pour l'équipe,
aussi l'alerte brute (le client n'y a pas accès) et les commentaires internes. Un champ précis cherche d'abord dans les
éléments relevés des alertes (keryx/observables.py). Le cloisonnement par client est appliqué par l'appelant (liste
des clients de l'utilisateur) : ce module ne fait qu'ajouter des conditions.
"""
from __future__ import annotations

import json
import re

from sqlalchemy import and_, or_, select

from .models import Comment, Observable, RawAlert, Ticket
from .observables import normaliser

PREFIXES = {"ip": "ip", "hote": "hote", "host": "hote", "agent": "agent", "regle": "regle", "rule": "regle",
            "compte": "compte", "user": "compte", "hash": "hash", "domaine": "domaine", "domain": "domaine",
            "ref": "ref"}
_PREFIXE = re.compile(r"^\s*([A-Za-zé]+)\s*:\s*(.+?)\s*$")


def analyser(q: str) -> tuple[str | None, str]:
    """(« champ », valeur) pour « champ:valeur » quand le champ est connu ; sinon (None, texte)."""
    m = _PREFIXE.match(q or "")
    if m and m.group(1).lower() in PREFIXES:
        return PREFIXES[m.group(1).lower()], m.group(2)[:200]
    return None, (q or "").strip()[:200]


def _like(v: str) -> str:
    return "%" + v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def condition(q: str, equipe: bool):
    """Condition SQL sur Ticket pour la recherche `q`. `equipe` : alertes brutes et commentaires internes inclus."""
    champ, v = analyser(q)
    if not v:
        return None
    like = _like(v)
    if champ == "ref":
        return Ticket.ref.ilike(like, escape="\\")
    if champ == "regle":
        return Ticket.rule_id == v
    if champ == "agent":
        return or_(Ticket.agent_name.ilike(like, escape="\\"), Ticket.agent_id == v, Ticket.agent_ip == v)
    if champ:
        n = normaliser(champ, v)
        conds = [Ticket.id.in_(select(Observable.ticket_id).where(Observable.kind == champ, Observable.value == n))] if n else []
        if champ == "ip":
            conds.append(Ticket.agent_ip == v)
        if champ == "hote":
            conds.append(Ticket.agent_name.ilike(like, escape="\\"))
        return or_(*conds) if conds else Ticket.id.is_(None)
    fields = [Ticket.ref, Ticket.title, Ticket.rule_description, Ticket.rule_id, Ticket.agent_name, Ticket.agent_ip,
              Ticket.body_html]
    conds = [f.ilike(like, escape="\\") for f in fields]
    cq = select(Comment.ticket_id).where(Comment.body_html.ilike(like, escape="\\"))
    if not equipe:
        cq = cq.where(Comment.visible_client.is_(True))
    conds.append(Ticket.id.in_(cq))
    if equipe:
        conds.append(Ticket.id.in_(select(RawAlert.ticket_id).where(RawAlert.payload.ilike(like, escape="\\"))))
    return or_(*conds)


def _champ_json(payload: str, valeur: str) -> str | None:
    """Nom du champ de l'alerte brute qui contient la valeur (« data.srcip »), ou None."""
    try:
        alert = json.loads(payload)
    except (TypeError, ValueError):
        return None
    vl = valeur.lower()

    def walk(obj, chemin):
        if isinstance(obj, dict):
            for k, x in obj.items():
                r = walk(x, f"{chemin}.{k}" if chemin else str(k))
                if r:
                    return r
        elif isinstance(obj, list):
            for x in obj[:200]:
                r = walk(x, chemin)
                if r:
                    return r
        elif isinstance(obj, (str, int)) and vl in str(obj).lower():
            return chemin
        return None
    return walk(alert, "")


def _extrait(texte: str, valeur: str, largeur: int = 60) -> str:
    plain = re.sub(r"<[^>]+>", " ", texte or "")
    i = plain.lower().find(valeur.lower())
    if i < 0:
        return ""
    debut, fin = max(0, i - largeur // 2), min(len(plain), i + len(valeur) + largeur // 2)
    return ("…" if debut else "") + " ".join(plain[debut:fin].split()) + ("…" if fin < len(plain) else "")


def ou_trouve(db, t: Ticket, q: str, equipe: bool) -> list[dict]:
    """Où la recherche a trouvé ce ticket : [{ou, champ, extrait}] (au plus quatre), pour l'afficher au résultat."""
    champ, v = analyser(q)
    out: list[dict] = []
    if not v:
        return out
    if champ in ("ip", "hote", "compte", "hash", "domaine"):
        n = normaliser(champ, v)
        if n and db.scalar(select(Observable.id).where(Observable.ticket_id == t.id, Observable.kind == champ,
                                                      Observable.value == n).limit(1)):
            raw = db.scalar(select(RawAlert.payload).where(RawAlert.ticket_id == t.id, RawAlert.payload.ilike(_like(n), escape="\\")).limit(1)) if equipe else None
            out.append({"ou": "alerte", "champ": _champ_json(raw, n) if raw else champ, "extrait": n})
        if champ == "ip" and t.agent_ip == v:
            out.append({"ou": "agent", "champ": "agent.ip", "extrait": v})
        return out[:4]
    if champ in ("ref", "regle", "agent"):
        return [{"ou": champ, "champ": champ, "extrait": {"ref": t.ref, "regle": t.rule_id, "agent": t.agent_name}[champ] or ""}]
    vl = v.lower()
    for nom, val in (("titre", t.title), ("règle", f"{t.rule_id} {t.rule_description or ''}"), ("agent", f"{t.agent_name or ''} {t.agent_ip or ''}")):
        if val and vl in val.lower():
            out.append({"ou": nom, "champ": None, "extrait": _extrait(val, v)})
    if t.body_html and vl in t.body_html.lower():
        out.append({"ou": "description", "champ": None, "extrait": _extrait(t.body_html, v)})
    if equipe and len(out) < 4:
        raw = db.scalar(select(RawAlert.payload).where(RawAlert.ticket_id == t.id, RawAlert.payload.ilike(_like(v), escape="\\")).limit(1))
        if raw:
            out.append({"ou": "alerte", "champ": _champ_json(raw, v), "extrait": v})
    if len(out) < 4:
        cq = select(Comment.body_html).where(Comment.ticket_id == t.id, Comment.body_html.ilike(_like(v), escape="\\"))
        if not equipe:
            cq = cq.where(Comment.visible_client.is_(True))
        c = db.scalar(cq.limit(1))
        if c:
            out.append({"ou": "commentaire", "champ": None, "extrait": _extrait(c, v)})
    return out[:4]


def suggestions(db, t: Ticket, exclure: set[str], limite: int = 5) -> list[dict]:
    """Valeurs relevées sur ce ticket que d'autres tickets du même client partagent : [{kind, value, tickets}]."""
    mine = db.execute(select(Observable.kind, Observable.value).where(Observable.ticket_id == t.id)).all()
    out = []
    for kind, value in mine:
        if kind == "hote" and value == (t.agent_name or "").lower():
            continue          # le même agent : déjà regroupé par le dédoublonnage, peu informatif
        if kind == "ip" and value == t.agent_ip:
            continue
        ids = db.scalars(select(Observable.ticket_id).where(
            and_(Observable.tenant_id == t.tenant_id, Observable.kind == kind, Observable.value == value,
                 Observable.ticket_id != t.id))).all()
        autres = [i for i in ids if i not in exclure]
        if autres:
            tickets = db.scalars(select(Ticket).where(Ticket.id.in_(autres)).order_by(Ticket.seq.desc()).limit(5)).all()
            out.append({"kind": kind, "value": value, "total": len(autres),
                        "tickets": [{"ref": x.ref, "title": x.title, "status": x.status} for x in tickets]})
    out.sort(key=lambda s: -s["total"])
    return out[:limite]
