#!/usr/bin/env python3
"""Lance la suite de tests de Keryx contre un vrai PostgreSQL embarqué (paquet « pgserver », sans Docker ni root).

Usage (Python 3.12 avec requirements-dev.txt, pgserver et « psycopg[binary] ») :
    python scripts/pg_tests.py [arguments de pytest]
Les tests créent une base jetable par test. En CI, utiliser plutôt un service PostgreSQL et KERYX_TEST_PG_URL.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pgserver

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as d:
    server = pgserver.get_server(Path(d) / "pg", cleanup_mode="stop")
    uri = server.get_uri().replace("postgresql://", "postgresql+psycopg://", 1)
    print("PostgreSQL :", server.psql("select version();").strip().splitlines()[2].strip())
    import pgserver._commands as pgc  # outils pg_dump / pg_restore embarqués
    bindir = str(Path(pgc.POSTGRES_BIN_PATH))
    env = {**os.environ, "KERYX_TEST_PG_URL": uri, "PYTHONWARNINGS": "ignore", "PATH": bindir + os.pathsep + os.environ["PATH"]}
    sys.exit(subprocess.call([sys.executable, "-m", "pytest", "-q", *sys.argv[1:]], cwd=root, env=env))
