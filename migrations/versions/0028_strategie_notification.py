"""stratégie de notification : criticité minimale par contact, moyen secondaire et date de son essai (PDIS IV.2.3.b, d)

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-26 23:00:00

Clients existants : chaque contact reçoit tous les tickets (comme avant), pas de moyen secondaire.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0028'
down_revision: Union[str, Sequence[str], None] = '0027'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('contacts_criticite', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('notif_secours_canal_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('notif_secours_teste_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_foreign_key('fk_tenants_notif_secours_canal', 'canaux_astreinte', ['notif_secours_canal_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_constraint('fk_tenants_notif_secours_canal', type_='foreignkey')
        batch_op.drop_column('notif_secours_teste_at')
        batch_op.drop_column('notif_secours_canal_id')
        batch_op.drop_column('contacts_criticite')
