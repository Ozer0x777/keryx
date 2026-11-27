"""réponse aux incidents (PRIS) : compréhension structurée, posture, cadre du rapport ; mesures d'endiguement ;
compléments du registre de crise (objectifs, arbitrages, critères de sortie, dérogations)

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-27 12:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0032'
down_revision: Union[str, Sequence[str], None] = '0031'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pris', sa.JSON(), nullable=True))
    with op.batch_alter_table('crisis_entries', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('decision_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('entite', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('risque', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('valide_par', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('valide_le', sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        'mesures_endiguement',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('ticket_id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('type', sa.String(length=16), nullable=False),
        sa.Column('libelle', sa.String(length=1000), nullable=False),
        sa.Column('etat', sa.String(length=16), nullable=False),
        sa.Column('decision_par', sa.String(length=200), nullable=True),
        sa.Column('commentaire', sa.Text(), nullable=True),
        sa.Column('cree_par', sa.String(length=64), nullable=False),
        sa.Column('cree_le', sa.DateTime(timezone=True), nullable=False),
        sa.Column('maj_par', sa.String(length=64), nullable=True),
        sa.Column('maj_le', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['ticket_id'], ['tickets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('mesures_endiguement', schema=None) as batch_op:
        batch_op.create_index('ix_mesures_endiguement_ticket_id', ['ticket_id'], unique=False)
        batch_op.create_index('ix_mesures_endiguement_tenant_id', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_table('mesures_endiguement')
    with op.batch_alter_table('crisis_entries', schema=None) as batch_op:
        for c in ('valide_le', 'valide_par', 'risque', 'entite', 'decision_id', 'parent_id'):
            batch_op.drop_column(c)
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.drop_column('pris')
