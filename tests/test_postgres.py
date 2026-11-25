"""Chemins propres à PostgreSQL (exécutés seulement avec KERYX_TEST_PG_URL, voir scripts/pg_tests.py)."""
import os
import threading
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import func, select

from keryx.db import Base, make_engine
from keryx.models import RawAlert, Ticket

from .conftest import ALERT_SSH_BRUTEFORCE, _pg_database, ingest

pytestmark = pytest.mark.skipif(not os.environ.get("KERYX_TEST_PG_URL"), reason="PostgreSQL requis")
ROOT = Path(__file__).parents[1]


def test_migrations_aller_retour_et_conformite_aux_modeles(monkeypatch):
    url, drop = _pg_database()
    try:
        monkeypatch.setenv("KERYX_DATABASE_URL", url)
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(ROOT / "migrations"))
        command.upgrade(cfg, "head")
        engine = make_engine(url)
        with engine.connect() as conn:
            assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
        engine.dispose()
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")  # on peut remonter après être redescendu
    finally:
        import gc
        gc.collect()
        drop()


def test_ingestion_concurrente_ne_cree_qu_un_ticket(app, db, world, alert):
    """Même règle, même agent, 12 requêtes simultanées : le verrou par client évite les doublons."""
    results, errors = [], []

    def send(i):
        payload = alert(ALERT_SSH_BRUTEFORCE)
        payload["id"] = f"concurrent-{i}"
        try:
            results.append(ingest(app, world["keys"]["ACME"], payload).json()["status"])
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=send, args=(i,)) for i in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    assert sorted(results).count("created") == 1 and results.count("merged") == 11
    db.rollback()
    assert db.scalar(select(func.count()).select_from(Ticket)) == 1
    assert db.scalar(select(func.count()).select_from(RawAlert)) == 12
    assert db.scalars(select(Ticket)).one().occurrences == 12


def test_references_sans_doublon_sous_charge(app, db, world, alert):
    """Deux règles différentes en parallèle : les références ACME-n restent uniques et consécutives."""
    def send(i):
        payload = alert(ALERT_SSH_BRUTEFORCE)
        payload["id"] = f"ref-{i}"
        payload["rule"]["id"] = str(7000 + i)
        ingest(app, world["keys"]["ACME"], payload)

    threads = [threading.Thread(target=send, args=(i,)) for i in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    db.rollback()
    refs = sorted(db.scalars(select(Ticket.ref)).all(), key=lambda r: int(r.split("-")[1]))
    assert refs == [f"ACME-{i}" for i in range(1, 11)]
