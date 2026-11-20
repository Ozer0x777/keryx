"""Script d'intégration Wazuh : file d'attente locale, erreurs définitives ou à réessayer. [README : aucune alerte perdue]"""
import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "integrations" / "wazuh" / "custom-keryx.py"


@pytest.fixture
def mod(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("custom_keryx", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(m, "LOG_FILE", str(tmp_path / "integrations.log"))
    monkeypatch.setattr(m.time, "sleep", lambda s: None)
    return m


class Resp:
    def __init__(self, status=201, body=b'{"status":"created","ticket":"ACME-1"}'):
        self.status, self._b = status, body

    def read(self, n=-1):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Opener:
    def __init__(self, *outcomes):
        self.outcomes, self.calls = list(outcomes), 0

    def open(self, req, timeout=None):
        self.calls += 1
        o = self.outcomes[min(self.calls - 1, len(self.outcomes) - 1)]
        if isinstance(o, Exception):
            raise o
        return o


def http_error(code):
    return urllib.error.HTTPError("https://k/x", code, "x", {}, io.BytesIO(b"{}"))


@pytest.mark.parametrize("code,expected", [(400, "definitif"), (413, "definitif"), (422, "definitif"),
                                           (401, "reessayer"), (403, "reessayer"), (429, "reessayer"), (500, "reessayer"), (503, "reessayer")])
def test_classement_des_erreurs(mod, code, expected):
    assert mod.post(Opener(http_error(code)), "https://k/x", "kx_cle", b"{}") == expected


def test_succes_et_erreurs_reseau(mod):
    assert mod.post(Opener(Resp()), "https://k/x", "kx_cle", b"{}") == "ok"
    assert mod.post(Opener(urllib.error.URLError("dns")), "https://k/x", "kx_cle", b"{}") == "reessayer"
    assert mod.post(Opener(TimeoutError()), "https://k/x", "kx_cle", b"{}") == "reessayer"


def alert_file(tmp_path, n=1):
    p = tmp_path / f"alert{n}.json"
    p.write_text(json.dumps({"id": f"a{n}", "rule": {"id": "5712", "level": 10}}))
    return str(p)


def test_cle_revoquee_garde_les_alertes_puis_les_rejoue(mod, tmp_path, monkeypatch):
    # Keryx répond 401 (clé en rotation) : l'alerte reste en file d'attente, rien n'est perdu
    opener = Opener(http_error(401))
    monkeypatch.setattr(mod, "_opener", lambda: opener)
    assert mod.main(["x", alert_file(tmp_path, 1), "kx_ancienne", "https://k/ingest"]) == 1
    assert mod.main(["x", alert_file(tmp_path, 2), "kx_ancienne", "https://k/ingest"]) == 1
    spool = sorted(Path(mod.SPOOL_DIR).glob("*.json"))
    assert len(spool) == 2
    # Nouvelle clé déployée : la prochaine alerte part, puis la file est vidée
    ok = Opener(Resp())
    monkeypatch.setattr(mod, "_opener", lambda: ok)
    assert mod.main(["x", alert_file(tmp_path, 3), "kx_nouvelle", "https://k/ingest"]) == 0
    assert list(Path(mod.SPOOL_DIR).glob("*.json")) == [] and ok.calls == 3


def test_erreur_definitive_ne_reste_pas_en_file(mod, tmp_path, monkeypatch):
    mod.spool(b'{"id":"mauvaise"}')
    monkeypatch.setattr(mod, "_opener", lambda: Opener(http_error(422), Resp()))
    assert mod.main(["x", alert_file(tmp_path), "kx", "https://k/ingest"]) == 1   # 422 sur l'alerte courante
    assert list(Path(mod.SPOOL_DIR).glob("*.json")) == []


def test_https_obligatoire_et_plafond_de_file(mod, tmp_path, monkeypatch):
    assert mod.main(["x", alert_file(tmp_path), "kx", "http://k/ingest"]) == 1
    monkeypatch.setattr(mod, "SPOOL_MAX_FILES", 2)
    for i in range(4):
        mod.spool(f'{{"i":{i}}}'.encode())
    assert len(list(Path(mod.SPOOL_DIR).glob("*.json"))) == 2   # au-delà du plafond : journalisé, pas de saturation du disque
