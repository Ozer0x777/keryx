"""parc d'agents Wazuh : réglages de l'API du manager par client, état des agents, historique des états (ADR-0030)

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-24 22:00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0019'
down_revision: Union[str, Sequence[str], None] = '0018'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('wazuh_api_url', sa.String(length=300), nullable=True))
        batch_op.add_column(sa.Column('wazuh_api_user', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('wazuh_api_password', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('wazuh_api_group', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('wazuh_manager_version', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('wazuh_agents_polled_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('wazuh_agents_error', sa.String(length=300), nullable=True))
    op.create_table('wazuh_agents',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('os_name', sa.String(length=120), nullable=True),
    sa.Column('os_version', sa.String(length=120), nullable=True),
    sa.Column('version', sa.String(length=32), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('groups', sa.JSON(), nullable=False),
    sa.Column('node', sa.String(length=120), nullable=True),
    sa.Column('last_keepalive', sa.DateTime(timezone=True), nullable=True),
    sa.Column('registered_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status_since', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'agent_id', name='uq_wazuh_agent')
    )
    with op.batch_alter_table('wazuh_agents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_wazuh_agents_tenant_id'), ['tenant_id'], unique=False)
    op.create_table('wazuh_agent_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('tenant_id', sa.String(length=36), nullable=False),
    sa.Column('agent_id', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('previous', sa.String(length=20), nullable=True),
    sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('wazuh_agent_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_wazuh_agent_events_tenant_id'), ['tenant_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_wazuh_agent_events_agent_id'), ['agent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_wazuh_agent_events_at'), ['at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('wazuh_agent_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_wazuh_agent_events_at'))
        batch_op.drop_index(batch_op.f('ix_wazuh_agent_events_agent_id'))
        batch_op.drop_index(batch_op.f('ix_wazuh_agent_events_tenant_id'))
    op.drop_table('wazuh_agent_events')
    with op.batch_alter_table('wazuh_agents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_wazuh_agents_tenant_id'))
    op.drop_table('wazuh_agents')
    with op.batch_alter_table('tenants', schema=None) as batch_op:
        for col in ('wazuh_agents_error', 'wazuh_agents_polled_at', 'wazuh_manager_version', 'wazuh_api_group',
                    'wazuh_api_password', 'wazuh_api_user', 'wazuh_api_url'):
            batch_op.drop_column(col)
