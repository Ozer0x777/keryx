"""Pilotage et rapports : tableau de bord manager, registre chronologique par client, rapport périodique.

[PDIS IV.2.1.bb registre chronologique par client ; PRIS VI.5.3.d registre des actions ; ISO/IEC 27035-1 : mesure de
la réponse] Le périmètre est toujours celui des clients de l'utilisateur ; l'Admin et le Client n'y ont pas accès.
Les exports CSV neutralisent l'injection de formules (OWASP : cellules débutant par = + - @).
"""
from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone

from fastapi import Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import audit, sla
from .ids import as_utc, rfc3339, utcnow
from .models import TERMINAL_STATUSES, Tenant, Ticket, User

MAX_DAYS = 366
MAX_TICKETS = 20000
OPEN = ("nouveau", "en_evaluation", "en_reponse")


def _day_start(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=timezone.utc)


def _hours(a, b) -> float:
    return (as_utc(b) - as_utc(a)).total_seconds() / 3600


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


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

    def load(db: DbSession, tenants: dict[str, Tenant]) -> list[Ticket]:
        rows = db.scalars(select(Ticket).where(Ticket.tenant_id.in_(list(tenants))).limit(MAX_TICKETS + 1)).all()
        if len(rows) > MAX_TICKETS:
            raise HTTPException(422, "Trop de tickets pour une même requête : restreindre le client ou la période.")
        return rows

    def compute(db: DbSession, tenants: dict[str, Tenant], start: datetime, end: datetime) -> dict:
        tickets = load(db, tenants)
        now = utcnow()
        created = [t for t in tickets if start <= as_utc(t.created_at) < end]
        closed = [t for t in tickets if t.closed_at and start <= as_utc(t.closed_at) < end]
        qualified = [t for t in created if t.qualified_at]
        by_status = Counter(t.status for t in tickets)
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
            "by_status": dict(by_status),
            "open_by_severity": {s: sev.get(s, 0) for s in ("Critique", "Élevée", "Moyenne", "Faible")},
            "workload": sorted(load_by.values(), key=lambda r: (-r["open"], r["name"])),
            "delays": {"qualification_hours_avg": _mean([_hours(t.created_at, t.qualified_at) for t in qualified]),
                       "resolution_hours_avg": _mean([_hours(t.created_at, t.closed_at) for t in closed]),
                       "qualified_count": len(qualified), "closed_count": len(closed)},
            "sla": {"resolution_within_target": within, "closed": len(closed),
                    "rate_percent": round(100 * within / len(closed)) if closed else None},
            "trend": list(per_day.values()),
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
        rows = [t for t in load(db, tenants) if s <= as_utc(t.created_at) < e or (t.closed_at and s <= as_utc(t.closed_at) < e)]
        rows.sort(key=lambda t: as_utc(t.created_at))
        out["client"] = {"key": tenant.key, "name": tenant.name}
        out["generated_at"] = rfc3339(utcnow())
        out["incidents"] = [{"ref": t.ref, "title": t.title, "detected_at": rfc3339(t.detected_at), "status": t.status,
                             "criticite_initiale": t.criticite_initiale, "gravite": t.gravite, "verdict": t.verdict,
                             "occurrences": t.occurrences, "closed_at": rfc3339(t.closed_at),
                             "mitre": [m["id"] for m in t.mitre]} for t in rows]
        audit.record(db, user.username, "report.period", "tenant", tenant.key, tenant.id,
                     {"from": out["period"]["from"], "to": out["period"]["to"], "incidents": len(rows)})
        commit(db)
        return out

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
        rows = [t for t in load(db, tenants) if s <= as_utc(t.detected_at) < e]
        rows.sort(key=lambda t: as_utc(t.detected_at))
        users = {u.id: u for u in db.scalars(select(User).where(User.id.in_({t.assignee_id for t in rows if t.assignee_id})))}
        header = ["reference", "detecte_le", "titre", "criticite_initiale", "gravite", "statut", "verdict", "assigne",
                  "occurrences", "regle", "agent", "mitre", "qualifie_le", "clos_le"]

        def line(t: Ticket) -> list:
            return [t.ref, rfc3339(t.detected_at), t.title, t.criticite_initiale, t.gravite or "", t.status,
                    t.verdict or "", users[t.assignee_id].username if t.assignee_id in users else "", t.occurrences,
                    t.rule_id, t.agent_name, " ".join(m["id"] for m in t.mitre), rfc3339(t.qualified_at) or "",
                    rfc3339(t.closed_at) or ""]

        audit.record(db, user.username, "registry.export", "tenant", tenant.key, tenant.id,
                     {"format": format, "rows": len(rows)})
        commit(db)
        if format == "json":
            return {"client": tenant.key, "generated_at": rfc3339(utcnow()),
                    "items": [dict(zip(header, line(t))) for t in rows]}
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(header)
        for t in rows:
            w.writerow([csv_cell(c) for c in line(t)])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="registre-{tenant.key}.csv"',
                                 "Cache-Control": "no-store"})
