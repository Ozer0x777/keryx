"""Pilotage et rapports : tableau de bord manager, registre chronologique par client, rapport périodique.

[PDIS IV.2.1.bb registre chronologique par client ; PRIS VI.5.3.d registre des actions ; ISO/IEC 27035-1 : mesure de
la réponse] Le périmètre est toujours celui des clients de l'utilisateur ; l'Admin et le Client n'y ont pas accès.
Les exports CSV neutralisent l'injection de formules (OWASP : cellules débutant par = + - @).
"""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone

from fastapi import Depends, HTTPException, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

from . import audit, sla, wazuh_agents
from .ids import as_utc, rfc3339, utcnow
from .models import AuditEntry, Notification, RawAlert, Tenant, Ticket, User, UserTenant

MAX_DAYS = 366
MAX_TICKETS = 20000
OPEN = ("nouveau", "en_evaluation", "en_reponse")


def _day_start(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=timezone.utc)


def _hours(a, b) -> float:
    return (as_utc(b) - as_utc(a)).total_seconds() / 3600


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


def _p90(values: list[float]) -> float | None:
    """90e centile (rang le plus proche) : 9 tickets sur 10 sont acquittés en ce délai ou moins."""
    if not values:
        return None
    v = sorted(values)
    return round(v[max(0, -(-9 * len(v) // 10) - 1)], 1)


def acquittement(tickets: list[Ticket]) -> dict:
    """Délai d'acquittement en minutes (ADR-0032) par criticité initiale, sur les tickets créés dans la période :
    moyenne et 90e centile des tickets acquittés, nombre de tickets pas encore acquittés."""
    out = {}
    for crit in ("Critique", "Élevée", "Moyenne", "Faible"):
        rows = [t for t in tickets if t.criticite_initiale == crit]
        d = [(as_utc(t.acquitted_at) - as_utc(t.detected_at)).total_seconds() / 60 for t in rows if t.acquitted_at]
        out[crit] = {"moyenne_min": _mean(d), "p90_min": _p90(d), "acquittes": len(d), "non_acquittes": len(rows) - len(d)}
    return out


def _stats(values: list[float]) -> dict:
    return {"min": round(min(values), 1), "moyenne": _mean(values), "max": round(max(values), 1), "n": len(values)} if values \
        else {"min": None, "moyenne": None, "max": None, "n": 0}


def _mois(start: datetime, end: datetime) -> list[tuple[str, datetime, datetime]]:
    """Mois de la période : (« AAAA-MM », début, fin exclue), bornés à la période."""
    out, d = [], start.replace(day=1)
    while d < end:
        nxt = (d.replace(day=28) + timedelta(days=4)).replace(day=1)
        out.append((d.strftime("%Y-%m"), max(d, start), min(nxt, end)))
        d = nxt
    return out


def indicateurs_pdis(db, tenants: dict, tickets: list[Ticket], start: datetime, end: datetime) -> dict:
    """Indicateurs minimaux de PDIS IV.5.1.e, f, g que Keryx peut produire (tickets, notifications, comptes du portail).
    Les indicateurs d'évènements, de collecteurs et de règles relèvent de Wazuh."""
    ids = list(tenants)
    dans = lambda v: v is not None and start <= as_utc(v) < end      # noqa: E731
    clos = [t for t in tickets if dans(t.closed_at)]
    crees = [t for t in tickets if dans(t.created_at)]
    # f) durée moyenne de qualification par typologie (catégorie ETSI ISI) et par gravité
    qualif: dict = {}
    for t in crees:
        if t.qualified_at:
            typo = (t.isi or {}).get("category") or "non classé"
            qualif.setdefault(typo, {}).setdefault(t.gravite or t.criticite_initiale, []).append(_hours(t.created_at, t.qualified_at))
    # f) délai entre détection et première notification envoyée au client, par gravité
    premieres = dict(db.execute(select(Notification.ticket_id, func.min(Notification.ts)).where(
        Notification.tenant_id.in_(ids), Notification.status == "envoye", Notification.canal_id.is_(None),
        Notification.ticket_id.in_([t.id for t in crees])).group_by(Notification.ticket_id)).all())
    notif: dict = {}
    for t in crees:
        if t.id in premieres:
            notif.setdefault(t.criticite_initiale, []).append((as_utc(premieres[t.id]) - as_utc(t.detected_at)).total_seconds() / 60)
    # e, g) séries mensuelles
    alertes = Counter(as_utc(r).strftime("%Y-%m") for r in db.scalars(select(RawAlert.received_at).where(
        RawAlert.tenant_id.in_(ids), RawAlert.received_at >= start, RawAlert.received_at < end)))
    tous = db.scalars(select(Ticket).where(Ticket.tenant_id.in_(ids), Ticket.created_at < end)).all()
    par_mois = []
    for mois, debut, fin in _mois(start, end):
        dedans = lambda v, d=debut, f=fin: v is not None and d <= as_utc(v) < f      # noqa: E731
        ouverts = Counter(t.criticite_initiale for t in tous
                          if as_utc(t.created_at) < fin and (t.closed_at is None or as_utc(t.closed_at) >= fin))  # noqa: B023
        par_mois.append({"mois": mois, "crees": sum(dedans(t.created_at) for t in tous),
                         "clos": sum(dedans(t.closed_at) for t in tous),
                         "averes": sum(dedans(t.qualified_at) and t.verdict == "vrai_positif_avere" for t in tous),
                         "alertes": alertes.get(mois, 0),
                         "ouverts_cumules": {c: ouverts.get(c, 0) for c in ("Critique", "Élevée", "Moyenne", "Faible")},
                         "resolution_moyenne_h": _mean([_hours(t.created_at, t.closed_at) for t in tous if dedans(t.closed_at)])})
    # e) les 20 règles les plus déclenchées (alertes reçues sur la période)
    top = db.execute(select(Ticket.rule_id, Ticket.rule_description, func.count(RawAlert.id)).join(
        RawAlert, RawAlert.ticket_id == Ticket.id).where(RawAlert.tenant_id.in_(ids), RawAlert.received_at >= start,
        RawAlert.received_at < end).group_by(Ticket.rule_id, Ticket.rule_description)
        .order_by(func.count(RawAlert.id).desc()).limit(20)).all()
    # e) comptes du portail et authentifications des comptes Client
    clients = db.scalars(select(User).join(UserTenant, UserTenant.user_id == User.id).where(
        UserTenant.tenant_id.in_(ids), User.role == "client")).unique().all()
    noms = {u.username for u in clients}
    # horodatage du journal : texte RFC 3339 (figé dans l'empreinte), comparé et découpé comme tel
    auth = Counter((e.action, e.ts[:7]) for e in db.scalars(select(AuditEntry).where(
        AuditEntry.action.in_(("auth.login_success", "auth.login_failed")), AuditEntry.actor.in_(noms),
        AuditEntry.ts >= rfc3339(start), AuditEntry.ts < rfc3339(end)))) if noms else Counter()
    # e, g) disponibilité du système d'envoi des notifications : part des envois réussis, par mois
    envois = Counter((as_utc(n.ts).strftime("%Y-%m"), n.status == "envoye") for n in db.scalars(select(Notification).where(
        Notification.tenant_id.in_(ids), Notification.ts >= start, Notification.ts < end,
        Notification.status.in_(("envoye", "echec")))))
    notifications_par_mois = [{"mois": m, "envoyees": envois.get((m, True), 0), "echecs": envois.get((m, False), 0),
                               "reussite_pourcent": round(100 * envois.get((m, True), 0)
                                                          / (envois.get((m, True), 0) + envois.get((m, False), 0)), 1)
                               if envois.get((m, True), 0) + envois.get((m, False), 0) else None}
                              for m, _, _ in _mois(start, end)]
    return {
        "notifications_par_mois": notifications_par_mois,
        "resolution_h": _stats([_hours(t.created_at, t.closed_at) for t in clos]),
        "qualification_par_typologie_h": {k: {g: _mean(v) for g, v in d.items()} for k, d in qualif.items()},
        "detection_notification_min": {c: _stats(v) for c, v in notif.items()},
        "par_mois": par_mois,
        "regles_les_plus_declenchees": [{"regle": r, "description": d, "alertes": n} for r, d, n in top],
        "portail": {"comptes_actifs": sum(u.active for u in clients),
                    "comptes_crees_par_mois": dict(Counter(as_utc(u.created_at).strftime("%Y-%m") for u in clients
                                                           if start <= as_utc(u.created_at) < end)),
                    "authentifications_par_mois": [{"mois": m, "reussies": auth.get(("auth.login_success", m), 0),
                                                    "echouees": auth.get(("auth.login_failed", m), 0)}
                                                   for m, _, _ in _mois(start, end)]},
    }


def capacite(db, settings) -> dict:
    """Stockage des incidents et des notifications (PDIS IV.2.1.cc, IV.2.3.k, IV.5.1.e) : taille de la base, espace
    du disque des pièces (stockage objet : capacité suivie par son propre outil)."""
    import os
    import shutil
    from sqlalchemy import text
    base = None
    try:
        if db.bind.dialect.name == "sqlite":
            base = db.execute(text("PRAGMA page_count")).scalar() * db.execute(text("PRAGMA page_size")).scalar()
        elif db.bind.dialect.name == "postgresql":
            base = db.execute(text("SELECT pg_database_size(current_database())")).scalar()
    except Exception:  # noqa: BLE001 - indicateur facultatif : jamais d'erreur du pilotage pour lui
        base = None
    disque = None
    if settings.storage_backend != "s3":
        os.makedirs(settings.attachments_dir, exist_ok=True)
        u = shutil.disk_usage(settings.attachments_dir)
        disque = {"total_octets": u.total, "libre_octets": u.free,
                  "remplissage_pourcent": round(100 * (u.total - u.free) / u.total, 1) if u.total else None}
    return {"base_octets": base, "disque_pieces": disque,
            "stockage_objet": settings.storage_backend == "s3"}


def csv_cell(value) -> str:
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit

    def scope(user: User, client: str | None, db: DbSession) -> dict[str, Tenant]:
        require_role(user, "analyst", "manager")
        tenants = {t.id: t for t in user.tenants}
        if client:
            tenants = {i: t for i, t in tenants.items() if t.key == client.upper()}
            if not tenants:
                raise HTTPException(404, "Client introuvable.")
        return tenants

    def period(start: date | None, end: date | None) -> tuple[datetime, datetime]:
        end_d = end or utcnow().date()
        start_d = start or end_d - timedelta(days=29)
        if start_d > end_d:
            raise HTTPException(422, "La date de début doit précéder la date de fin.")
        if (end_d - start_d).days >= MAX_DAYS:
            raise HTTPException(422, f"Période limitée à {MAX_DAYS} jours.")
        return _day_start(start_d), _day_start(end_d) + timedelta(days=1)

    def load(db: DbSession, tenants: dict[str, Tenant], start: datetime | None = None, end: datetime | None = None,
             field: str = "both") -> list[Ticket]:
        """Tickets du périmètre. Avec une période : ceux créés ou clos dans la fenêtre (field='both'), détectés
        dans la fenêtre (field='detected'), plus, pour 'both', tous les tickets ouverts (charge, échéances)."""
        q = select(Ticket).where(Ticket.tenant_id.in_(list(tenants)))
        if start is not None and end is not None:
            if field == "detected":
                q = q.where(Ticket.detected_at >= start, Ticket.detected_at < end)
            else:
                q = q.where(or_(Ticket.status.in_(OPEN), Ticket.created_at.between(start, end - timedelta(microseconds=1)),
                                Ticket.closed_at.between(start, end - timedelta(microseconds=1))))
        rows = db.scalars(q.limit(MAX_TICKETS + 1)).all()
        if len(rows) > MAX_TICKETS:
            raise HTTPException(422, "Trop de tickets pour une même requête : restreindre le client ou la période.")
        return rows

    def compute(db: DbSession, tenants: dict[str, Tenant], start: datetime, end: datetime) -> dict:
        tickets = load(db, tenants, start, end)
        now = utcnow()
        created = [t for t in tickets if start <= as_utc(t.created_at) < end]
        closed = [t for t in tickets if t.closed_at and start <= as_utc(t.closed_at) < end]
        qualified = [t for t in created if t.qualified_at]
        by_status = dict(db.execute(select(Ticket.status, func.count()).where(Ticket.tenant_id.in_(list(tenants)))
                                    .group_by(Ticket.status)).all())
        open_t = [t for t in tickets if t.status in OPEN]
        sev = Counter((t.gravite or t.criticite_initiale) for t in open_t)
        users = {u.id: u for u in db.scalars(select(User).where(User.id.in_({t.assignee_id for t in open_t if t.assignee_id})))}
        load_by = {}
        for t in open_t:
            key = users[t.assignee_id].display_name if t.assignee_id in users else "Non assigné"
            row = load_by.setdefault(key, {"name": key, "open": 0, "overdue": 0})
            row["open"] += 1
            row["overdue"] += int(sla.state(t, tenants.get(t.tenant_id), now)["overdue"])
        # Respect de l'échéance de résolution pour les tickets clos dans la période
        within = 0
        for t in closed:
            target = sla.targets(tenants.get(t.tenant_id), t.gravite or t.criticite_initiale)["resolution"]
            within += int(_hours(t.created_at, t.closed_at) <= target)
        days = (end - start).days
        per_day = {(start + timedelta(days=i)).date().isoformat(): {"date": (start + timedelta(days=i)).date().isoformat(),
                                                                    "created": 0, "closed": 0} for i in range(days)}
        for t in created:
            per_day[as_utc(t.created_at).date().isoformat()]["created"] += 1
        for t in closed:
            per_day[as_utc(t.closed_at).date().isoformat()]["closed"] += 1
        return {
            "period": {"from": start.date().isoformat(), "to": (end - timedelta(days=1)).date().isoformat()},
            "totals": {"created": len(created), "closed": len(closed), "open": len(open_t),
                       "overdue": sum(int(sla.state(t, tenants.get(t.tenant_id), now)["overdue"]) for t in open_t)},
            "by_status": by_status,
            "open_by_severity": {s: sev.get(s, 0) for s in ("Critique", "Élevée", "Moyenne", "Faible")},
            "workload": sorted(load_by.values(), key=lambda r: (-r["open"], r["name"])),
            "delays": {"qualification_hours_avg": _mean([_hours(t.created_at, t.qualified_at) for t in qualified]),
                       "resolution_hours_avg": _mean([_hours(t.created_at, t.closed_at) for t in closed]),
                       "qualified_count": len(qualified), "closed_count": len(closed)},
            "acquittement": acquittement(created),
            "indicateurs_pdis": {**indicateurs_pdis(db, tenants, tickets, start, end), "capacite": capacite(db, ctx.settings)},
            "sla": {"resolution_within_target": within, "closed": len(closed),
                    "rate_percent": round(100 * within / len(closed)) if closed else None},
            "trend": list(per_day.values()),
            # Parc d'agents Wazuh (ADR-0030) : état courant et disponibilité sur la période, si un relevé existe.
            "parc": wazuh_agents.summary(db, tenants, start, end),
        }

    @app.get("/api/v1/dashboard")
    def dashboard(client: str | None = None, start: date | None = Query(default=None, alias="from"),
                  to: date | None = None, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Tableau de bord manager (le manager voit tous ses clients ; l'analyste, les siens)."""
        tenants = scope(user, client, db)
        s, e = period(start, to)
        out = compute(db, tenants, s, e)
        out["generated_at"] = rfc3339(utcnow())
        out["clients"] = sorted(t.key for t in tenants.values())
        return out

    @app.get("/api/v1/reports/period")
    def period_report(client: str | None = None, start: date | None = Query(default=None, alias="from"),
                      to: date | None = None, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Rapport périodique d'un client : synthèse chiffrée + liste des incidents de la période."""
        require_role(user, "analyst", "manager")
        if not client:
            raise HTTPException(422, "Indiquer le client du rapport.")
        tenants = scope(user, client, db)
        s, e = period(start, to)
        out = compute(db, tenants, s, e)
        tenant = next(iter(tenants.values()))
        rows = [t for t in load(db, tenants, s, e) if s <= as_utc(t.created_at) < e or (t.closed_at and s <= as_utc(t.closed_at) < e)]
        rows.sort(key=lambda t: as_utc(t.created_at))
        out["client"] = {"key": tenant.key, "name": tenant.name}
        # Délai d'acquittement : dans le rapport remis au client seulement si le manager l'a choisi (ADR-0032).
        out.pop("indicateurs_pdis", None)      # indicateurs de pilotage : supports des comités, pas du rapport client
        out["acquittement_inclus"] = bool(tenant.acquittement_rapport)
        if not tenant.acquittement_rapport:
            out.pop("acquittement")
        out["generated_at"] = rfc3339(utcnow())
        out["incidents"] = [{"ref": t.ref, "title": t.title, "detected_at": rfc3339(t.detected_at), "status": t.status,
                             "criticite_initiale": t.criticite_initiale, "gravite": t.gravite, "verdict": t.verdict,
                             "occurrences": t.occurrences, "closed_at": rfc3339(t.closed_at),
                             "mitre": [m["id"] for m in t.mitre]} for t in rows]
        audit.record(db, user.username, "report.period", "tenant", tenant.key, tenant.id,
                     {"from": out["period"]["from"], "to": out["period"]["to"], "incidents": len(rows)})
        commit(db)
        return out

    @app.get("/api/v1/registre-notifications")
    def notification_registry(client: str, start: date | None = Query(default=None, alias="from"), to: date | None = None,
                              format: str = "json", user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Registre centralisé et chronologique des notifications d'un client [PDIS IV.2.3.h, i, j]."""
        from .models import Notification
        require_role(user, "analyst", "manager")
        tenants = scope(user, client, db)
        if format not in ("json", "csv"):
            raise HTTPException(422, "Format attendu : json ou csv.")
        s, e = period(start, to) if (start or to) else (_day_start(date(2000, 1, 1)), _day_start(utcnow().date()) + timedelta(days=1))
        tenant = next(iter(tenants.values()))
        rows = db.execute(select(Notification, Ticket.ref).outerjoin(Ticket, Ticket.id == Notification.ticket_id)
                          .where(Notification.tenant_id == tenant.id, Notification.ts >= s, Notification.ts < e)
                          .order_by(Notification.ts).limit(MAX_TICKETS + 1)).all()
        if len(rows) > MAX_TICKETS:
            raise HTTPException(422, "Trop de notifications pour une même requête : restreindre la période.")
        header = ["date", "ticket", "mode", "destinataire", "objet", "statut", "tentatives", "motif", "code_reponse"]

        def objet(n) -> str:
            if n.canal_id:
                try:
                    return json.loads(n.content).get("subject") or ""
                except ValueError:
                    return ""
            return n.content.partition("\n")[0]

        def line(n, ref) -> list:
            return [rfc3339(n.ts), ref or "", n.channel, n.recipient, objet(n), n.status, n.attempts or 0,
                    n.motif or "client", n.http_status if n.http_status is not None else ""]

        audit.record(db, user.username, "notifications.export", "tenant", tenant.key, tenant.id,
                     {"format": format, "rows": len(rows)})
        commit(db)
        if format == "json":
            return {"client": tenant.key, "generated_at": rfc3339(utcnow()),
                    "items": [dict(zip(header, line(n, ref), strict=True)) for n, ref in rows]}
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(header)
        for n, ref in rows:
            w.writerow([csv_cell(v) for v in line(n, ref)])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="notifications-{tenant.key}.csv"',
                                 "Cache-Control": "no-store"})

    @app.get("/api/v1/registre")
    def registry(client: str, start: date | None = Query(default=None, alias="from"), to: date | None = None,
                 format: str = "json", user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Registre chronologique des incidents d'un client, exportable en CSV [PDIS IV.2.1.bb]."""
        require_role(user, "analyst", "manager")
        tenants = scope(user, client, db)
        if format not in ("json", "csv"):
            raise HTTPException(422, "Format attendu : json ou csv.")
        s, e = period(start, to) if (start or to) else (_day_start(date(2000, 1, 1)), _day_start(utcnow().date()) + timedelta(days=1))
        tenant = next(iter(tenants.values()))
        rows = [t for t in load(db, tenants, s, e, "detected") if s <= as_utc(t.detected_at) < e]
        rows.sort(key=lambda t: as_utc(t.detected_at))
        users = {u.id: u for u in db.scalars(select(User).where(User.id.in_({t.assignee_id for t in rows if t.assignee_id})))}
        header = ["reference", "detecte_le", "titre", "criticite_initiale", "gravite", "statut", "verdict", "assigne",
                  "occurrences", "regle", "version_regle", "agent", "collecteur", "niveau_classification", "mitre",
                  "qualifie_le", "clos_le"]

        def line(t: Ticket) -> list:
            return [t.ref, rfc3339(t.detected_at), t.title, t.criticite_initiale, t.gravite or "", t.status,
                    t.verdict or "", users[t.assignee_id].username if t.assignee_id in users else "", t.occurrences,
                    t.rule_id, t.rule_version or "", t.agent_name, t.collecteur or "", t.niveau_classification,
                    " ".join(m["id"] for m in t.mitre), rfc3339(t.qualified_at) or "",
                    rfc3339(t.closed_at) or ""]

        audit.record(db, user.username, "registry.export", "tenant", tenant.key, tenant.id,
                     {"format": format, "rows": len(rows)})
        commit(db)
        if format == "json":
            return {"client": tenant.key, "generated_at": rfc3339(utcnow()),
                    "items": [dict(zip(header, line(t), strict=True)) for t in rows]}
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(header)
        for t in rows:
            w.writerow([csv_cell(c) for c in line(t)])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="registre-{tenant.key}.csv"',
                                 "Cache-Control": "no-store"})
