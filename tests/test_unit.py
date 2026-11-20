"""Tests unitaires : UUIDv7, horodatage, intégration Wazuh."""
import json
import subprocess
import sys
import uuid
from pathlib import Path

from keryx.ids import parse_wazuh_timestamp, rfc3339, uuid7


def test_uuid7_version_et_ordre():
    a, b = uuid7(), uuid7()
    assert uuid.UUID(a).version == 7 and uuid.UUID(a).variant == uuid.RFC_4122
    assert a[:8] <= b[:8]  # préfixe temporel croissant


def test_horodatage_wazuh_rfc3339():
    dt = parse_wazuh_timestamp("2026-11-20T14:12:07.412+0000")
    assert rfc3339(dt) == "2026-11-20T14:12:07.412Z"


def test_script_wazuh_refuse_http_clair(tmp_path):
    script = Path(__file__).parents[1] / "integrations" / "wazuh" / "custom-keryx.py"
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"rule": {"id": "1", "level": 10}}))
    r = subprocess.run([sys.executable, str(script), str(alert), "kx_test", "http://keryx.local/api"],
                       capture_output=True, text=True)
    assert r.returncode == 1  # HTTPS obligatoire


def test_limite_de_debit_partagee_entre_deux_applications(settings):
    """Deux instances sur la même base (deux processus) partagent la même limite. [ADR-0010]"""
    from keryx.api import create_app
    settings.rate_limit_backend = "db"
    a, b = create_app(settings), create_app(settings)
    from fastapi.testclient import TestClient
    ca, cb = TestClient(a), TestClient(b)
    codes = []
    for i in range(12):  # limite : 10 essais par identifiant sur 5 minutes, répartis sur les deux instances
        c = ca if i % 2 == 0 else cb
        codes.append(c.post("/api/v1/auth/login", json={"username": "x", "password": "y"}).status_code)
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    # En mémoire (par processus), chaque instance aurait compté séparément : 12 essais passeraient sans 429
    settings.rate_limit_backend = "memory"
    m1, m2 = TestClient(create_app(settings)), TestClient(create_app(settings))
    mem = [(m1 if i % 2 == 0 else m2).post("/api/v1/auth/login", json={"username": "x", "password": "y"}).status_code for i in range(12)]
    assert 429 not in mem
