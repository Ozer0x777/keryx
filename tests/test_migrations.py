"""Migrations Alembic : le schéma migré correspond exactement aux modèles. [ISO/IEC 27002:2022 8.32]"""
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient

from keryx.api import create_app
from keryx.config import Settings
from keryx.db import Base, make_engine

from .conftest import SECRET_KEY

ROOT = Path(__file__).parents[1]


def test_upgrade_head_conforme_aux_modeles(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/migre.db"
    monkeypatch.setenv("KERYX_DATABASE_URL", url)
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "head")
    engine = make_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
    # L'application démarre sur la base migrée, sans création automatique du schéma.
    app = create_app(Settings(database_url=url, secret_key=SECRET_KEY, auto_create_schema=False,
                              cookie_secure=False, web_dist=str(tmp_path / "x")))
    assert TestClient(app).get("/healthz").status_code == 200
    command.downgrade(cfg, "base")


def test_mise_a_niveau_d_une_base_deja_remplie(tmp_path, monkeypatch):
    """Régression : une migration qui ajoute une colonne NOT NULL sans valeur par défaut échoue sur une base
    contenant déjà des tickets (vu sur une vraie base). On remplit chaque version, puis on monte à la dernière."""
    import sqlalchemy as sa
    url = f"sqlite:///{tmp_path}/ancienne.db"
    monkeypatch.setenv("KERYX_DATABASE_URL", url)
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "0001")
    engine = make_engine(url)
    meta = sa.MetaData()
    meta.reflect(engine)

    def fill(table_name, **given):
        t = meta.tables[table_name]
        row = dict(given)
        for c in t.columns:
            if c.name in row or c.nullable or c.server_default is not None:
                continue
            import datetime
            py = c.type.python_type
            row[c.name] = ({bool: False, int: 1, datetime.datetime: datetime.datetime(2026, 1, 1),
                            dict: {}, list: []}.get(py, "x" * 8))
        with engine.begin() as conn:
            conn.execute(t.insert().values(**row))

    fill("tenants", id="t1", key="ACME", name="Acme")
    fill("tickets", id="k1", tenant_id="t1", seq=1, ref="ACME-1", title="t", criticite_initiale="Moyenne",
         rule_id="1", rule_level=10, rule_description="d")
    fill("notifications", id="n1", tenant_id="t1", ticket_id="k1", channel="email", recipient="a@b.c", content="x", status="echec")
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        assert conn.execute(sa.text("select crisis from tickets")).scalar() in (0, False)
        # Les lignes des tables filles survivent à la recréation de la table « tickets » (pas de cascade)
        assert conn.execute(sa.text("select count(*) from notifications")).scalar() == 1
        assert conn.execute(sa.text("select attempts from notifications")).scalar() == 0
        assert conn.execute(sa.text("select count(*) from tickets")).scalar() == 1
