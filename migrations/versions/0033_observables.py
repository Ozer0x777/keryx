"""éléments relevés dans les alertes (IP, hôtes, comptes, empreintes, domaines) : recherche par valeur et tickets
« peut-être liés » ; reprise des alertes brutes déjà conservées

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-28 10:00:00
"""
import json
from datetime import datetime, timezone
from typing import Sequence, Union
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision: str = '0033'
down_revision: Union[str, Sequence[str], None] = '0032'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'observables',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('ticket_id', sa.String(length=36), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['ticket_id'], ['tickets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ticket_id', 'kind', 'value'),
    )
    op.create_index('ix_observables_tenant_id', 'observables', ['tenant_id'])
    op.create_index('ix_observables_ticket_id', 'observables', ['ticket_id'])
    op.create_index('ix_observable_valeur', 'observables', ['tenant_id', 'kind', 'value'])
    # Reprise : éléments des alertes brutes déjà conservées (par lots, sans charger toute la table).
    from keryx.observables import extraire
    conn = op.get_bind()
    now = datetime.now(timezone.utc)
    vus: set[tuple[str, str, str]] = set()
    last = ''
    while True:
        rows = conn.execute(sa.text("SELECT id, ticket_id, tenant_id, payload FROM raw_alerts WHERE id > :last ORDER BY id LIMIT 500"),
                            {"last": last}).fetchall()
        if not rows:
            break
        last = rows[-1][0]
        lot = []
        for _id, ticket_id, tenant_id, payload in rows:
            try:
                alert = json.loads(payload)
            except (TypeError, ValueError):
                continue
            if not isinstance(alert, dict):
                continue
            for kind, value in extraire(alert):
                if (ticket_id, kind, value) not in vus:
                    vus.add((ticket_id, kind, value))
                    lot.append({"id": str(uuid4()), "tenant_id": tenant_id, "ticket_id": ticket_id, "kind": kind,
                                "value": value, "created_at": now})
        if lot:
            conn.execute(sa.text("INSERT INTO observables (id, tenant_id, ticket_id, kind, value, created_at) "
                                 "VALUES (:id, :tenant_id, :ticket_id, :kind, :value, :created_at)"), lot)


def downgrade() -> None:
    op.drop_index('ix_observable_valeur', table_name='observables')
    op.drop_index('ix_observables_ticket_id', table_name='observables')
    op.drop_index('ix_observables_tenant_id', table_name='observables')
    op.drop_table('observables')
