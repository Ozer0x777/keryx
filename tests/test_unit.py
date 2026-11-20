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
