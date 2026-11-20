"""Accès base de données (SQLAlchemy 2). SQLite en test, PostgreSQL en production."""
from __future__ import annotations

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def make_engine(url: str, immediate: bool = True) -> Engine:
    is_sqlite = url.startswith("sqlite")
    engine = create_engine(
        url,
        # PostgreSQL : session en UTC, pour que les dates relues soient toujours en UTC (RFC 3339).
        connect_args={"check_same_thread": False, "timeout": 15} if is_sqlite else {"options": "-c timezone=UTC"},
        future=True,
    )
    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - configuration
            dbapi_conn.isolation_level = None  # SQLAlchemy gère BEGIN lui-même
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=15000")
            cur.close()

        @event.listens_for(engine, "begin")
        def _sqlite_begin(conn):  # pragma: no cover - configuration
            # BEGIN IMMEDIATE : une seule transaction d'écriture à la fois, ce qui évite les lectures
            # périmées (numérotation des tickets, chaîne d'audit). Lecture seule : BEGIN simple.
            conn.exec_driver_sql("BEGIN IMMEDIATE" if immediate else "BEGIN")
    return engine


def make_session_factory(engine: Engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def serialize_writes(db: Session, lock_id: int) -> None:
    """Verrou de transaction pour les sections qui doivent être sérialisées
    (chaîne d'audit). PostgreSQL : verrou consultatif ; SQLite : déjà sérialisé (BEGIN IMMEDIATE)."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_id})
