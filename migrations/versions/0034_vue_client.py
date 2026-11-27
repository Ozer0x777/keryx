"""portail client : titre en mots de client et résumé « Ce qui se passe », écrits par l'équipe

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-28 14:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0034'
down_revision: Union[str, Sequence[str], None] = '0033'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('titre_client', sa.String(length=300), nullable=True))
        batch_op.add_column(sa.Column('resume_client', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('resume_client_le', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.drop_column('resume_client_le')
        batch_op.drop_column('resume_client')
        batch_op.drop_column('titre_client')
