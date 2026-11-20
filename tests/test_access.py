"""Authentification, rôles et cloisonnement. [PDIS IV.3.8.g, IV.3.9 ; RFC 6238 ; ASVS V6/V7/V8]"""
import pyotp
from fastapi.testclient import TestClient

from keryx.models import User

from .conftest import ALERT_SSH_BRUTEFORCE, PASSWORD, ingest, login, totp_secret


def test_mot_de_passe_seul_ne_suffit_pas(app, db, world):
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD}).status_code == 200
    assert c.get("/api/v1/tickets").status_code == 401  # 2FA obligatoire


def test_mauvais_totp_refuse(app, db, world):
    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD})
    assert c.post("/api/v1/auth/totp", json={"code": "000000"}).status_code == 401


def test_rejeu_totp_refuse(app, db, world):
    login(app, db, "analyst_acme")
    user = db.query(User).filter_by(username="analyst_acme").one()
    db.refresh(user)
    used = pyotp.TOTP(totp_secret(app, user)).at(user.last_totp_step * 30)  # le code qui vient de servir
    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD})
    assert c.post("/api/v1/auth/totp", json={"code": used}).status_code == 401


def test_verrouillage_apres_echecs_totp(app, db, world):
    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"username": "client_acme", "password": PASSWORD})
    for _ in range(5):
        assert c.post("/api/v1/auth/totp", json={"code": "000000"}).status_code == 401
    r = c.post("/api/v1/auth/login", json={"username": "client_acme", "password": PASSWORD})
    assert r.status_code == 401  # verrouillé, message générique


def test_pas_de_verrouillage_par_mot_de_passe(app, db, world):
    """Un inconnu ne doit pas pouvoir bloquer un compte avec de mauvais mots de passe."""
    c = TestClient(app)
    for _ in range(6):
        c.post("/api/v1/auth/login", json={"username": "client_acme", "password": "mauvais-mot-de-passe"})
    assert TestClient(app).post("/api/v1/auth/login",
                                json={"username": "client_acme", "password": PASSWORD}).status_code == 200


def test_csrf_exige(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "analyst_acme")
    del c.headers["X-CSRF-Token"]
    r = c.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>test</p>"})
    assert r.status_code == 403


def test_cloisonnement_entre_clients(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "analyst_acme")
    refs = [t["ref"] for t in c.get("/api/v1/tickets").json()["items"]]
    assert refs == ["ACME-1"]
    assert c.get("/api/v1/tickets/DELTA-1").status_code == 404  # existence non révélée
    cl = login(app, db, "client_delta")
    assert [t["ref"] for t in cl.get("/api/v1/tickets").json()["items"]] == ["DELTA-1"]
    assert cl.get("/api/v1/tickets/ACME-1").status_code == 404


def test_manager_voit_ses_clients(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "manager")
    assert sorted(t["ref"] for t in c.get("/api/v1/tickets").json()["items"]) == ["ACME-1", "DELTA-1"]


def test_admin_sans_acces_aux_tickets(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "admin")
    assert c.get("/api/v1/tickets").status_code == 403
    assert c.get("/api/v1/tickets/ACME-1").status_code == 403


def test_client_ne_voit_pas_les_commentaires_internes(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>interne</p>", "visible_client": False})
    a.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>pour le client</p>", "visible_client": True})
    cl = login(app, db, "client_acme")
    bodies = [x["body_html"] for x in cl.get("/api/v1/tickets/ACME-1").json()["comments"]]
    assert bodies == ["<p>pour le client</p>"]
    # Un client ne peut pas qualifier un ticket
    r = cl.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    assert r.status_code == 403


def test_commentaire_assaini(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/comments",
               json={"body_html": '<p onclick="x()">ok</p><script>alert(1)</script><a href="javascript:x">l</a>'})
    body = r.json()["body_html"]
    assert "onclick" not in body and "<script" not in body and "javascript:" not in body


def test_en_tetes_de_securite(app, db, world):
    c = login(app, db, "analyst_acme")
    r = c.get("/api/v1/me")
    assert r.headers["cache-control"] == "no-store"             # RFC 9111
    assert "max-age" in r.headers["strict-transport-security"]  # RFC 6797
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_revue_des_comptes_reservee_admin(app, db, world):
    # PDIS IV.3.4.b : revue mensuelle des comptes et des droits.
    r = login(app, db, "admin").get("/api/v1/admin/revue-comptes")
    assert r.status_code == 200
    items = {u["username"]: u for u in r.json()["items"]}
    assert items["client_acme"]["role"] == "client" and items["client_acme"]["clients"] == ["ACME"]
    assert {"last_login_at", "recovery_codes_left", "locked", "active"} <= set(items["admin"])
    for user in ("analyst_acme", "client_acme"):
        assert login(app, db, user).get("/api/v1/admin/revue-comptes").status_code == 403
