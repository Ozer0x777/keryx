"""source Wazuh d'un client dans l'indexeur (nom du manager ou du cluster) : cloisonnement d'un indexeur partagé (ADR-0031)

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-26 09:00:00

Colonne vide pour les clients existants. Un client qui partage déjà son indexeur avec un autre, avec des motifs
d'index qui peuvent se recouvrir, voit le contexte Wazuh refusé (409) jusqu'à ce qu'un Admin règle la source de chacun.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0021'
down_revision: Union[str, Sequence[str], None] = '0020'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('wazuh_indexer_source', sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.drop_column('wazuh_indexer_source')
