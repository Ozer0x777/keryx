"""délai d'acquittement : première action humaine sur le ticket, choix du rapport client (ADR-0032)

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-26 21:00:00

Tickets existants : non acquittés (aucune donnée inventée). Clients existants : délai absent du rapport client.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0023'
down_revision: Union[str, Sequence[str], None] = '0022'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('acquitted_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('acquitted_by', sa.String(length=64), nullable=True))
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('acquittement_rapport', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('acquittement_rapport')
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.drop_column('acquitted_by')
        batch_op.drop_column('acquitted_at')
