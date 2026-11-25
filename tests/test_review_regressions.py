"""Tests de non-régression des constats de la revue de code (interne et indépendante)."""
import hashlib
import importlib.util
import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from keryx import audit
from keryx.ids import utcnow
from keryx.models import AuditEntry, Session, Ticket

from .conftest import ALERT_SSH_BRUTEFORCE, PASSWORD, ingest, login, next_code


# ---------------------------------------------------------------- authentification
def test_totp_refuse_si_compte_verrouille_meme_avec_autre_session(app, db, world):
    """Revue #1 / indépendante #3 : plusieurs sessions intermédiaires ouvertes avant le verrouillage."""
    sessions = [TestClient(app) for _ in range(3)]
    for c in sessions:
        assert c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD}).status_code == 200
    for _ in range(5):
        sessions[0].post("/api/v1/auth/totp", json={"code": "000000"})
    r = sessions[1].post("/api/v1/auth/totp", json={"code": next_code(app, db, "analyst_acme")})
    assert r.status_code == 401


def test_identifiant_inconnu_et_mauvais_mot_de_passe_indiscernables(app, world):
    """Revue #11 / indépendante #8 : même statut, même message."""
    a = TestClient(app).post("/api/v1/auth/login", json={"username": "analyst_acme", "password": "faux-mot-de-passe"})
    b = TestClient(app).post("/api/v1/auth/login", json={"username": "personne", "password": "faux-mot-de-passe"})
    assert a.status_code == b.status_code == 401 and a.json()["detail"] == b.json()["detail"]


def test_identifiant_avec_retour_ligne_refuse(app, world):
    r = TestClient(app).post("/api/v1/auth/login", json={"username": "evil\n<13>1 FAUX", "password": "x" * 12})
    assert r.status_code == 422


def test_session_expiree_par_inactivite(app, db, world):
    c = login(app, db, "analyst_acme")
    db.execute(update(Session).values(last_seen_at=utcnow() - timedelta(minutes=31)))
    db.commit()
    assert c.get("/api/v1/me").status_code == 401


def test_acces_refuse_journalise(app, db, world, alert):
    """Indépendante #15 : un accès hors périmètre est tracé."""
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "analyst_acme")
    assert c.get("/api/v1/tickets/DELTA-1").status_code == 404
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "ticket.access_denied")).first() is not None


# ---------------------------------------------------------------- journal d'audit
def test_syslog_sans_injection_de_ligne(app, db, world):
    """Revue #2 / indépendante #12."""
    e = AuditEntry(seq=1, ts="2026-11-20T00:00:00.000Z", actor="evil\n<110>1 faux", action="x", details={},
                   prev_hash="0" * 64, hash="0" * 64)
    assert "\n" not in audit.to_syslog(e, "keryx")


def test_cle_invalide_ne_remplit_pas_le_journal(app, db, world, alert):
    """Revue #3 / indépendante #7 : au-delà de la limite, plus d'écriture dans l'audit."""
    codes = [ingest(app, "kx_faux", alert(ALERT_SSH_BRUTEFORCE)).status_code for _ in range(50)]
    rejected = db.scalars(select(AuditEntry).where(AuditEntry.action == "ingest.rejected_key")).all()
    assert len(rejected) <= 20 and 429 in codes


def test_chaine_non_recalculable_sans_la_cle(app, db, world, alert):
    """Indépendante #2 : recalculer les empreintes (SHA-256 simple) ne suffit plus."""
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    entries = db.scalars(select(AuditEntry).order_by(AuditEntry.seq)).all()
    prev = "0" * 64
    for e in entries:  # un attaquant modifie un acteur puis recalcule une chaîne SHA-256
        e.actor = "falsifie"
        e.prev_hash = prev
        e.hash = hashlib.sha256((prev + json.dumps({"x": e.seq})).encode()).hexdigest()
        prev = e.hash
    db.commit()
    assert audit.verify_chain(db)[0] is False


def test_troncature_detectee_par_point_de_controle(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    checkpoint = audit.head(db)
    db.delete(db.get(AuditEntry, checkpoint[0]))
    db.commit()
    assert audit.verify_chain(db)[0] is True              # sans point de contrôle : invisible
    assert audit.verify_chain(db, checkpoint)[0] is False  # avec point de contrôle : détecté


# ---------------------------------------------------------------- concurrence
def test_ingestion_concurrente_sans_erreur_ni_doublon(app, db, world, alert):
    """Revue #4-5 / indépendante #1, #5 : 16 alertes simultanées pour un même client."""
    key = world["keys"]["ACME"]
    results = []

    def send(i):
        a = alert(ALERT_SSH_BRUTEFORCE)
        a["id"] = f"concurrent-{i}"
        a["rule"]["id"] = str(90000 + i)
        results.append(ingest(app, key, a).status_code)

    threads = [threading.Thread(target=send, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(201) == 16
    refs = [t.ref for t in db.scalars(select(Ticket))]
    assert len(set(refs)) == 16
    assert audit.verify_chain(db) == (True, None)


# ---------------------------------------------------------------- alertes mal formées
MALFORMED = [
    ("agent", "oops"), ("decoder", "oops"), ("data", "oops"), ("timestamp", 12345),
    ("rule.mitre", ["T1110"]), ("agent.ip", {"x": 1}), ("agent.labels", ["vital"]),
    ("rule.groups", "sshd"), ("agent.id", "9" * 500), ("rule.description", "x" * 5000),
]


@pytest.mark.parametrize("path,value", MALFORMED)
def test_alerte_mal_formee_jamais_500(app, world, alert, path, value):
    """Revue #9 / indépendante #4."""
    a = alert(ALERT_SSH_BRUTEFORCE)
    a["id"] = f"malformed-{path}"
    target = a
    *parents, leaf = path.split(".")
    for p in parents:
        target = target[p]
    target[leaf] = value
    r = ingest(app, world["keys"]["ACME"], a)
    assert r.status_code in (200, 201, 202, 400, 422), r.text


@pytest.mark.parametrize("raw", [
    b'{"rule": {"id": "1", "level": Infinity}}',
    b'{"rule": {"id": "1", "level": 99}}',
    b"[" * 100_000 + b"]" * 100_000,
])
def test_corps_invalide_erreur_propre(app, world, raw):
    r = TestClient(app).post("/api/v1/ingest/wazuh", content=raw,
                             headers={"Authorization": f"Bearer {world['keys']['ACME']}",
                                      "Content-Type": "application/json"})
    assert r.status_code in (400, 413, 422) and r.headers["content-type"].startswith("application/problem+json")


# ---------------------------------------------------------------- qualification
def test_requalification_partielle_et_gravite_recalculee(app, db, world, alert):
    """Revue #7 / indépendante #6."""
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/qualification",
           json={"verdict": "vrai_positif_avere", "dommages": "limites", "importance": "standard", "impact": "poste isolé"})
    r = a.post("/api/v1/tickets/ACME-1/qualification", json={"importance": "vital"})
    t = a.get("/api/v1/tickets/ACME-1").json()
    assert t["impact"] == "poste isolé"                 # non effacé
    assert t["gravite"] == "Élevée" and r.json()["rex_required"] is True  # limites × vital


def test_verdict_fige_apres_evaluation(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "vrai_positif_avere", "dommages": "graves"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_reponse"})
    r = a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    assert r.status_code == 409


def test_ticket_clos_non_requalifiable(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    assert a.post("/api/v1/tickets/ACME-1/qualification",
                  json={"verdict": "vrai_positif_avere"}).status_code == 409


# ---------------------------------------------------------------- divers
def test_pas_de_swagger_cdn(app):
    """Revue #8 / indépendante #13."""
    assert TestClient(app).get("/api/docs").status_code == 404


def test_erreur_interne_au_format_rfc9457(app, world, monkeypatch):
    import keryx.api as api_mod
    monkeypatch.setattr(api_mod, "ingest_alert", lambda *a, **k: 1 / 0)
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/ingest/wazuh", json={"rule": {"id": "1", "level": 10}, "id": "boom"},
               headers={"Authorization": f"Bearer {world['keys']['ACME']}"})
    assert r.status_code == 500 and r.headers["content-type"].startswith("application/problem+json")
    assert "ZeroDivision" not in r.text


def test_pagination(app, db, world, alert):
    for i in range(3):
        a = alert(ALERT_SSH_BRUTEFORCE)
        a["id"], a["rule"]["id"] = f"p{i}", str(70000 + i)
        ingest(app, world["keys"]["ACME"], a)
    c = login(app, db, "analyst_acme")
    page = c.get("/api/v1/tickets?limit=2&offset=0").json()
    assert len(page["items"]) == 2 and page["limit"] == 2
    assert len(c.get("/api/v1/tickets?limit=2&offset=2").json()["items"]) == 1


def test_limite_de_debit_connexion(app, world):
    c = TestClient(app)
    codes = [c.post("/api/v1/auth/login", json={"username": "client_acme", "password": "faux-mot-de-passe"}).status_code
             for _ in range(12)]
    assert 429 in codes


def test_export_iodef_interdit_au_client(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "client_acme")
    assert c.get("/api/v1/tickets/ACME-1/iodef").status_code == 403


def test_deconnexion(app, db, world):
    c = login(app, db, "analyst_acme")
    assert c.post("/api/v1/auth/logout").status_code == 200
    assert c.get("/api/v1/me").status_code == 401


# ---------------------------------------------------------------- script Wazuh
def _load_script():
    path = Path(__file__).parents[1] / "integrations" / "wazuh" / "custom-keryx.py"
    spec = importlib.util.spec_from_file_location("custom_keryx", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _server(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_script_ne_suit_pas_les_redirections(tmp_path, monkeypatch):
    """Indépendante #10 : la clé ne doit jamais partir vers un autre serveur."""
    mod = _load_script()
    monkeypatch.setattr(mod, "LOG_FILE", str(tmp_path / "log"))
    seen = []

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    target = _server(Target)

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/")
            self.end_headers()

        def log_message(self, *a):
            pass

    redirect = _server(Redirect)
    opener = mod.urllib.request.build_opener(mod._NoRedirect())
    outcome = mod.post(opener, f"http://127.0.0.1:{redirect.server_port}/", "kx_secret", b"{}")
    assert outcome != "ok" and seen == []


def test_script_file_d_attente_puis_renvoi(tmp_path, monkeypatch):
    """Revue #12 : Keryx injoignable → alerte conservée sur disque, renvoyée ensuite."""
    mod = _load_script()
    monkeypatch.setattr(mod, "LOG_FILE", str(tmp_path / "log"))
    monkeypatch.setattr(mod, "SPOOL_DIR", str(tmp_path / "spool"))
    mod.spool(b'{"id": "a1"}')
    assert len(list((tmp_path / "spool").glob("*.json"))) == 1
    received = []

    class Ok(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(201); self.end_headers(); self.wfile.write(b'{"status": "created"}')

        def log_message(self, *a):
            pass

    srv = _server(Ok)
    opener = mod.urllib.request.build_opener(mod._NoRedirect())
    mod.flush_spool(opener, f"http://127.0.0.1:{srv.server_port}/", "kx_test")
    assert received == [b'{"id": "a1"}'] and not list((tmp_path / "spool").glob("*.json"))


def test_script_reponse_non_json_ne_plante_pas(tmp_path, monkeypatch):
    mod = _load_script()
    monkeypatch.setattr(mod, "LOG_FILE", str(tmp_path / "log"))

    class Html(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"<html>proxy</html>")

        def log_message(self, *a):
            pass

    srv = _server(Html)
    opener = mod.urllib.request.build_opener(mod._NoRedirect())
    assert mod.post(opener, f"http://127.0.0.1:{srv.server_port}/", "kx_test", b"{}") == "ok"
