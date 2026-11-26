"""battement de cœur de la chaîne Wazuh vers Keryx, par client (ADR-0032, partie 3)

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-27 01:00:00

Désactivé pour chaque client existant. Un message du registre des notifications peut ne concerner aucun ticket
(battement manquant ou rétabli) : sa référence au ticket devient facultative.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0025'
down_revision: Union[str, Sequence[str], None] = '0024'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('battement_active', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column('battement_periode_min', sa.Integer(), server_default='5', nullable=False))
        batch_op.add_column(sa.Column('battement_delai_min', sa.Integer(), server_default='15', nullable=False))
        batch_op.add_column(sa.Column('battement_depuis', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('battement_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('battement_source', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('battement_manquant_at', sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.alter_column('ticket_id', existing_type=sa.String(length=36), nullable=True)


def downgrade() -> None:
    op.execute("DELETE FROM notifications WHERE ticket_id IS NULL")
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.alter_column('ticket_id', existing_type=sa.String(length=36), nullable=False)
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        for c in ('battement_manquant_at', 'battement_source', 'battement_at', 'battement_depuis',
                  'battement_delai_min', 'battement_periode_min', 'battement_active'):
            batch_op.drop_column(c)
