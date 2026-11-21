"""contexte wazuh : lien vers l'alerte et lecture de l'indexeur, par client

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-21 20:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0017'
down_revision: Union[str, Sequence[str], None] = '0016'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMNS = ('wazuh_dashboard_url', 'wazuh_indexer_url', 'wazuh_index_pattern', 'wazuh_indexer_user',
           'wazuh_indexer_password', 'wazuh_tls_verify', 'wazuh_ca_pem')


def upgrade() -> None:
    # Tout est vide par défaut : la fonction reste masquée tant qu'un Admin ne l'a pas réglée (ADR-0021).
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('wazuh_dashboard_url', sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column('wazuh_indexer_url', sa.String(length=300), nullable=True))
        batch_op.add_column(sa.Column('wazuh_index_pattern', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('wazuh_indexer_user', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('wazuh_indexer_password', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('wazuh_tls_verify', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column('wazuh_ca_pem', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        for name in reversed(COLUMNS):
            batch_op.drop_column(name)
