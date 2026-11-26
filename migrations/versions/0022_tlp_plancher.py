"""politique du client : TLP plancher réglé par le manager (ADR-0033)

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-26 18:00:00

Colonne vide pour les clients existants : aucun plancher, comportement inchangé (tickets en TLP:AMBER).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0022'
down_revision: Union[str, Sequence[str], None] = '0021'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tlp_plancher', sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('tlp_plancher')
