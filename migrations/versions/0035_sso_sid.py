"""sessions SSO : identifiant de session du fournisseur (sid), pour la déconnexion par le canal arrière

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-28 18:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0035'
down_revision: Union[str, Sequence[str], None] = '0034'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sso_sid', sa.String(length=255), nullable=True))
        batch_op.create_index('ix_sessions_sso_sid', ['sso_sid'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_index('ix_sessions_sso_sid')
        batch_op.drop_column('sso_sid')
