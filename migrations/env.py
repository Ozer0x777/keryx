"""Migrations Keryx (Alembic). URL de base : KERYX_DATABASE_URL."""
from alembic import context

from keryx import models  # noqa: F401  (enregistre les tables)
from keryx.config import Settings
from keryx.db import Base, make_engine

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=Settings().database_url, target_metadata=target_metadata,
                      literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(Settings().database_url)
    with engine.connect() as connection:
        # render_as_batch : modifications de colonnes compatibles SQLite
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
