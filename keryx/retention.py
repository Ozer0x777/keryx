"""Rétention des alertes brutes [PDIS IV.2.2.w : 6 mois minimum ; ISM Wazuh : 12 mois].
Un client dont le contexte se conserve toute la prestation (PDIS IV.5.3.6, réglage par défaut) n'est jamais purgé.

Seules les alertes brutes de tickets CLOS plus anciennes que la durée du client sont supprimées. Le ticket, son
registre des actions et ses pièces (dont la destruction suit le cycle de vie tracé, PRIS VI.2.4) sont conservés.
Chaque purge est inscrite dans le journal d'audit avec le nombre d'alertes supprimées et la date limite.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from . import audit
from .config import MIN_RETENTION_MONTHS, Settings
from .models import TERMINAL_STATUSES, Observable, RawAlert, SystemSetting, Tenant, Ticket

SETTING_KEY = "retention_months"


def default_months(db: DbSession, settings: Settings) -> tuple[int, str]:
    """Durée par défaut des clients sans valeur propre, et sa provenance : réglage Admin > variable d'environnement > minimum."""
    row = db.get(SystemSetting, SETTING_KEY)
    if row is not None:
        return max(MIN_RETENTION_MONTHS, int(row.value.get("months", MIN_RETENTION_MONTHS))), "reglage"
    if os.environ.get("KERYX_RETENTION_MONTHS"):
        return settings.retention_months, "environnement"
    return MIN_RETENTION_MONTHS, "defaut"


def run(db: DbSession, settings: Settings, now: datetime, actor: str, dry_run: bool = True) -> list[dict]:
    report = []
    default, _ = default_months(db, settings)
    for tenant in db.scalars(select(Tenant).order_by(Tenant.key)).all():
        if tenant.conserver_contexte:
            report.append({"client": tenant.key, "months": None, "before": None, "alerts": 0, "conserve": True})
            continue
        months = max(MIN_RETENTION_MONTHS, tenant.retention_months or default)
        cutoff = now - timedelta(days=30 * months)
        ids = select(Ticket.id).where(Ticket.tenant_id == tenant.id, Ticket.status.in_(TERMINAL_STATUSES),
                                      Ticket.closed_at.is_not(None), Ticket.closed_at < cutoff)
        cond = (RawAlert.tenant_id == tenant.id, RawAlert.ticket_id.in_(ids), RawAlert.received_at < cutoff)
        count = db.scalar(select(func.count()).select_from(RawAlert).where(*cond)) or 0
        if count and not dry_run:
            db.execute(delete(RawAlert).where(*cond))
            # Les éléments relevés dans ces alertes suivent la même durée.
            db.execute(delete(Observable).where(Observable.tenant_id == tenant.id, Observable.ticket_id.in_(ids))
                       .execution_options(synchronize_session=False))
            audit.record(db, actor, "retention.purge", "tenant", tenant.key, tenant.id,
                         {"alertes_supprimees": count, "avant_le": cutoff.date().isoformat(), "mois": months})
        report.append({"client": tenant.key, "months": months, "before": cutoff.date().isoformat(), "alerts": count,
                       "conserve": False})
    return report
