"""Migrations Keryx (Alembic). URL de base : KERYX_DATABASE_URL."""
from alembic import context
from sqlalchemy import event

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
    sqlite = engine.dialect.name == "sqlite"
    if sqlite:
        # SQLite recrée une table pour certaines modifications (mode « batch » : copie, suppression, renommage).
        # Avec les clés étrangères actives, supprimer l'ancienne table supprimerait EN CASCADE les lignes des
        # tables filles (notifications, alertes brutes, commentaires…). On les désactive donc pendant la migration
        # (la commande ne peut pas changer dans une transaction : on la pose à la connexion) puis on contrôle.
        @event.listens_for(engine, "connect")
        def _fk_off(dbapi_conn, _record):  # pragma: no cover - configuration
            dbapi_conn.execute("PRAGMA foreign_keys=OFF")
    with engine.connect() as connection:
        # render_as_batch : modifications de colonnes compatibles SQLite
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
            if sqlite:
                broken = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
                if broken:
                    raise RuntimeError(f"Migration annulée : {len(broken)} ligne(s) orpheline(s) après migration.")


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
