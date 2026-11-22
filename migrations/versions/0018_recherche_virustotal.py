"""recherche d'empreinte sur VirusTotal : clé par utilisateur, registre des recherches

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-22 18:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0018'
down_revision: Union[str, Sequence[str], None] = '0017'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clé d'API VirusTotal de l'utilisateur, chiffrée (ADR-0022). Vide : aucune recherche possible pour ce compte.
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('vt_api_key', sa.Text(), nullable=True))
    op.create_table('hash_lookups',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('ticket_id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('hash', sa.String(length=64), nullable=False),
    sa.Column('hash_type', sa.String(length=8), nullable=False),
    sa.Column('source_type', sa.String(length=16), nullable=False),
    sa.Column('source_id', sa.String(length=64), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.Column('actor', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.ForeignKeyConstraint(['ticket_id'], ['tickets.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('hash_lookups', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_hash_lookups_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_hash_lookups_ticket_id'), ['ticket_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('hash_lookups', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_hash_lookups_ticket_id'))
        batch_op.drop_index(batch_op.f('ix_hash_lookups_tenant_id'))
    op.drop_table('hash_lookups')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('vt_api_key')
