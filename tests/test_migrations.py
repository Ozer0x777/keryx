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
