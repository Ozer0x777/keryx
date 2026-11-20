"""Rétention des alertes brutes [PDIS IV.2.2.w : 6 mois minimum ; ISM Wazuh : 12 mois].

Seules les alertes brutes de tickets CLOS plus anciennes que la durée du client sont supprimées. Le ticket, son
registre des actions et ses pièces (dont la destruction suit le cycle de vie tracé, PRIS VI.2.4) sont conservés.
Chaque purge est inscrite dans le journal d'audit avec le nombre d'alertes supprimées et la date limite.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from . import audit
from .config import Settings
from .models import TERMINAL_STATUSES, RawAlert, Tenant, Ticket


def run(db: DbSession, settings: Settings, now: datetime, actor: str, dry_run: bool = True) -> list[dict]:
    report = []
    for tenant in db.scalars(select(Tenant).order_by(Tenant.key)).all():
        months = max(6, tenant.retention_months or settings.retention_months)
        cutoff = now - timedelta(days=30 * months)
        ids = select(Ticket.id).where(Ticket.tenant_id == tenant.id, Ticket.status.in_(TERMINAL_STATUSES),
                                      Ticket.closed_at.is_not(None))
        cond = (RawAlert.tenant_id == tenant.id, RawAlert.ticket_id.in_(ids), RawAlert.received_at < cutoff)
        count = db.scalar(select(func.count()).select_from(RawAlert).where(*cond)) or 0
        if count and not dry_run:
            db.execute(delete(RawAlert).where(*cond))
            audit.record(db, actor, "retention.purge", "tenant", tenant.key, tenant.id,
                         {"alertes_supprimees": count, "avant_le": cutoff.date().isoformat(), "mois": months})
        report.append({"client": tenant.key, "months": months, "before": cutoff.date().isoformat(), "alerts": count})
    return report
