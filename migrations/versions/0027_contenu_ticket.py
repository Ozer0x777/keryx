"""contenu du ticket (PDIS IV.2.1.w) : niveau de classification, version de la règle, collecteur

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-26 22:30:00

Tickets existants : « Non protégé », version de règle et collecteur inconnus (la fiche lit le collecteur dans
l'alerte brute quand elle existe encore).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0027'
down_revision: Union[str, Sequence[str], None] = '0026'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('niveau_classification_defaut', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('version_regles', sa.String(length=120), nullable=True))
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('niveau_classification', sa.String(length=40), server_default='Non protégé',
                                      nullable=False))
        batch_op.add_column(sa.Column('rule_version', sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column('collecteur', sa.String(length=200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tickets', schema=None) as batch_op:
        batch_op.drop_column('collecteur')
        batch_op.drop_column('rule_version')
        batch_op.drop_column('niveau_classification')
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('version_regles')
        batch_op.drop_column('niveau_classification_defaut')
