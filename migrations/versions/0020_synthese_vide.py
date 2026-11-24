"""synthèse : un champ vide à l'écran (« <p><br></p> », espaces) devient vide en base, comme le fait désormais l'API

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-24 23:30:00

Sans cette reprise, un ticket dont la synthèse avait été enregistrée vide avant la mise à jour n'apparaîtrait pas dans
la vue « Dossiers incomplets » (ADR-0025). Une image seule reste un contenu. Pas de retour arrière : rien n'est perdu.
"""
import html
import re
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0020'
down_revision: Union[str, Sequence[str], None] = '0019'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

FIELDS = ('chronologie', 'mode_operatoire', 'perimetre', 'rex_html')


def _blank(value):
    if value is None:
        return False
    if '<img' in value:
        return False
    text = html.unescape(re.sub(r'<[^>]*>', '', value)).replace('\xa0', ' ').strip()
    return text == ''


def upgrade() -> None:
    conn = op.get_bind()
    tickets = sa.table('tickets', sa.column('id', sa.String), *[sa.column(f, sa.Text) for f in FIELDS])
    rows = conn.execute(sa.select(tickets.c.id, *[tickets.c[f] for f in FIELDS])).all()
    for row in rows:
        blank = {f: None for f in FIELDS if getattr(row, f) is not None and _blank(getattr(row, f))}
        if blank:
            conn.execute(tickets.update().where(tickets.c.id == row.id).values(**blank))


def downgrade() -> None:
    pass
