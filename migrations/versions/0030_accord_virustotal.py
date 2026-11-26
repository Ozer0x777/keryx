"""accord du client avant une recherche VirusTotal (PDIS IV.1.g)

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-26 23:45:00

Faux pour tous les clients existants : la recherche reste refusée jusqu'à l'accord enregistré par le manager.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0030'
down_revision: Union[str, Sequence[str], None] = '0029'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('virustotal_autorise', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('virustotal_autorise')
