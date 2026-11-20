"""Délais cibles (SLA) par gravité : qualification et résolution, en heures.

[PDIS IV.2.1.e, r, s : échelle définie avec le commanditaire.] Les valeurs par défaut ci-dessous sont des
hypothèses de travail, à valider avec chaque client ; elles se règlent par client (Administration > Clients).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .ids import as_utc, rfc3339, utcnow
from .models import TERMINAL_STATUSES, Tenant, Ticket

DEFAULT_SLA = {
    "Critique": {"qualification": 1, "resolution": 8},
    "Élevée": {"qualification": 4, "resolution": 24},
    "Moyenne": {"qualification": 24, "resolution": 72},
    "Faible": {"qualification": 72, "resolution": 168},
}


def targets(tenant: Tenant | None, severity: str) -> dict:
    custom = (tenant.sla or {}) if tenant else {}
    return {**DEFAULT_SLA.get(severity, DEFAULT_SLA["Faible"]), **(custom.get(severity) or {})}


def state(t: Ticket, tenant: Tenant | None, now: datetime | None = None) -> dict:
    """Échéances et dépassements. La qualification se mesure sur la criticité initiale (la gravité n'existe
    pas encore) ; la résolution sur la gravité qualifiée si elle existe."""
    now = now or utcnow()
    open_ = t.status not in TERMINAL_STATUSES and t.status != "cloture"
    created = as_utc(t.created_at)
    q_due = r_due = None
    if t.qualified_at is None and open_:
        q_due = created + timedelta(hours=targets(tenant, t.criticite_initiale)["qualification"])
    if open_:
        r_due = created + timedelta(hours=targets(tenant, t.gravite or t.criticite_initiale)["resolution"])
    overdue = bool((q_due and q_due < now) or (r_due and r_due < now))
    return {"due_qualification": rfc3339(q_due), "due_resolution": rfc3339(r_due), "overdue": overdue}
