"""astreinte et escalade de l'équipe : canaux, réglages par client, suivi sur le ticket et le registre (ADR-0032)

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-26 23:00:00

Tout est désactivé par défaut : aucun canal, astreinte inactive pour chaque client existant.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0024'
down_revision: Union[str, Sequence[str], None] = '0023'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'canaux_astreinte',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('kind', sa.String(length=24), nullable=False),
        sa.Column('target_enc', sa.Text(), nullable=False),
        sa.Column('target_label', sa.String(length=300), nullable=False),
        sa.Column('secret_enc', sa.Text(), nullable=True),
        sa.Column('include_title', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('astreinte_active', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch_op.add_column(sa.Column('astreinte_criticites', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('astreinte_delais', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('astreinte_canal_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('escalade_canal_id', sa.String(length=36), nullable=True))
        batch_op.create_foreign_key('fk_tenants_astreinte_canal', 'canaux_astreinte', ['astreinte_canal_id'], ['id'])
        batch_op.create_foreign_key('fk_tenants_escalade_canal', 'canaux_astreinte', ['escalade_canal_id'], ['id'])
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('astreinte_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('escalade_at', sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.add_column(sa.Column('canal_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('motif', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('http_status', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_notifications_canal', 'canaux_astreinte', ['canal_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('notifications', schema=None) as batch_op:
        batch_op.drop_constraint('fk_notifications_canal', type_='foreignkey')
        batch_op.drop_column('http_status')
        batch_op.drop_column('motif')
        batch_op.drop_column('canal_id')
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.drop_column('escalade_at')
        batch_op.drop_column('astreinte_at')
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_constraint('fk_tenants_escalade_canal', type_='foreignkey')
        batch_op.drop_constraint('fk_tenants_astreinte_canal', type_='foreignkey')
        batch_op.drop_column('escalade_canal_id')
        batch_op.drop_column('astreinte_canal_id')
        batch_op.drop_column('astreinte_delais')
        batch_op.drop_column('astreinte_criticites')
        batch_op.drop_column('astreinte_active')
    op.drop_table('canaux_astreinte')
