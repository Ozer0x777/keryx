"""suivi du ticket par le client et actions demandées au client (PDIS IV.2.3.l)

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-26 23:30:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0029'
down_revision: Union[str, Sequence[str], None] = '0028'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('etat_client', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('demande_client', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('etat_client_at', sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        'actions_client',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('ticket_id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('libelle', sa.String(length=500), nullable=False),
        sa.Column('etat', sa.String(length=16), server_default='a_faire', nullable=False),
        sa.Column('commentaire', sa.Text(), nullable=True),
        sa.Column('cree_par', sa.String(length=64), nullable=False),
        sa.Column('cree_le', sa.DateTime(timezone=True), nullable=False),
        sa.Column('maj_par', sa.String(length=64), nullable=True),
        sa.Column('maj_le', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['ticket_id'], ['tickets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('actions_client', schema=None) as batch_op:
        batch_op.create_index('ix_actions_client_ticket_id', ['ticket_id'], unique=False)
        batch_op.create_index('ix_actions_client_tenant_id', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_table('actions_client')
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.drop_column('etat_client_at')
        batch_op.drop_column('demande_client')
        batch_op.drop_column('etat_client')
