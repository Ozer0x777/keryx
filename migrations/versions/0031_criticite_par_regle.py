"""criticité initiale imposée par règle Wazuh, réglée par le manager pour chaque client

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-27 10:00:00

Vide pour les clients existants : la criticité reste calculée depuis le niveau Wazuh.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0031'
down_revision: Union[str, Sequence[str], None] = '0030'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('criticite_regles', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('criticite_regles')
