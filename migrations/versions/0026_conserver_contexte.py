"""conservation du contexte des incidents pendant toute la prestation, par client (PDIS IV.5.3.6)

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-26 22:00:00

Vrai pour tous les clients, y compris existants : la purge des alertes brutes ne s'applique plus qu'aux clients pour
lesquels l'Admin la choisit explicitement.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0026'
down_revision: Union[str, Sequence[str], None] = '0025'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('conserver_contexte', sa.Boolean(), server_default=sa.true(), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('conserver_contexte')
