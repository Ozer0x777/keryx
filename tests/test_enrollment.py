"""Enrôlement du TOTP par le titulaire, à sa première connexion. [PDIS IV.3.9.d à h ; RFC 6238]"""
import pyotp
from fastapi.testclient import TestClient

from keryx.models import User
from sqlalchemy import select

from .conftest import login

TEMP = "mot-de-passe-temporaire-1"


def create(app, db, world, username="nouveau"):
    a = login(app, db, "admin")
    r = a.post("/api/v1/admin/users", json={"username": username, "display_name": "Nouveau", "role": "analyst",
                                              "clients": ["ACME"], "password": TEMP})
    assert r.status_code == 201, r.text


def test_parcours_complet_d_enrolement(app, db, world):
    create(app, db, world)
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "nouveau", "password": TEMP}).json() == {"next": "enroll"}
    # Tant que l'enrôlement n'est pas fait : ni TOTP, ni accès
    assert c.post("/api/v1/auth/totp", json={"code": "123456"}).status_code == 401
    assert c.get("/api/v1/tickets").status_code == 401
    assert c.post("/api/v1/auth/enroll/finish", json={"code": "123456", "new_password": "un-autre-mot-de-passe"}).status_code == 409  # pas démarré
    start = c.post("/api/v1/auth/enroll/start").json()
    assert start["totp_uri"].startswith("otpauth://totp/") and len(start["totp_secret"]) >= 16
    # Code faux, mot de passe identique au temporaire : refusés
    assert c.post("/api/v1/auth/enroll/finish", json={"code": "000000", "new_password": "un-autre-mot-de-passe"}).status_code == 401
    code = pyotp.TOTP(start["totp_secret"]).now()
    assert c.post("/api/v1/auth/enroll/finish", json={"code": code, "new_password": TEMP}).status_code == 422
    done = c.post("/api/v1/auth/enroll/finish", json={"code": code, "new_password": "un-autre-mot-de-passe"})
    assert done.status_code == 200 and len(done.json()["recovery_codes"]) == 10 and done.json()["csrf_token"]
    c.headers["X-CSRF-Token"] = done.json()["csrf_token"]
    assert c.get("/api/v1/me").json()["username"] == "nouveau"
    # Le secret n'est connu que du titulaire : l'Admin ne peut pas le lire, et l'ancien mot de passe ne marche plus
    assert "totp_secret" not in login(app, db, "admin").get("/api/v1/admin/users").text
    assert TestClient(app).post("/api/v1/auth/login", json={"username": "nouveau", "password": TEMP}).status_code == 401


def test_connexion_normale_apres_enrolement(app, db, world):
    create(app, db, world, "suivant")
    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"username": "suivant", "password": TEMP})
    start = c.post("/api/v1/auth/enroll/start").json()
    code = pyotp.TOTP(start["totp_secret"]).now()
    done = c.post("/api/v1/auth/enroll/finish", json={"code": code, "new_password": "un-autre-mot-de-passe"}).json()
    c2 = TestClient(app)
    assert c2.post("/api/v1/auth/login", json={"username": "suivant", "password": "un-autre-mot-de-passe"}).json() == {"next": "totp"}
    assert c2.post("/api/v1/auth/enroll/start").status_code == 409          # déjà enrôlé : le secret ne peut pas être écrasé
    assert c2.post("/api/v1/auth/totp", json={"code": code}).status_code == 401  # le code d'enrôlement ne rejoue pas
    assert c2.post("/api/v1/auth/totp", json={"recovery_code": done["recovery_codes"][0]}).status_code == 200


def test_reinitialisation_2fa_impose_un_nouvel_enrolement(app, db, world):
    adm = login(app, db, "admin")
    old = login(app, db, "analyst_acme")
    assert old.get("/api/v1/me").status_code == 200
    assert adm.post("/api/v1/admin/users/analyst_acme/reset-2fa").status_code == 200
    assert old.get("/api/v1/me").status_code == 401                       # sessions fermées
    adm.post("/api/v1/admin/users/analyst_acme/reset-password", json={"password": TEMP})
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": TEMP}).json() == {"next": "enroll"}
    start = c.post("/api/v1/auth/enroll/start").json()
    r = c.post("/api/v1/auth/enroll/finish", json={"code": pyotp.TOTP(start["totp_secret"]).now(), "new_password": "mot-de-passe-definitif-9"})
    assert r.status_code == 200
    db.rollback()
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().enrolled is True


def test_enrolement_sans_session_ou_pour_un_autre_compte(app, db, world):
    c = TestClient(app)
    assert c.post("/api/v1/auth/enroll/start").status_code == 401
    assert c.post("/api/v1/auth/enroll/finish", json={"code": "123456", "new_password": "x" * 12}).status_code == 401
    # Un compte déjà enrôlé (rôle quelconque) ne peut pas relancer un enrôlement qui écraserait son secret
    c.post("/api/v1/auth/login", json={"username": "manager", "password": "correct-horse-battery-staple"})
    assert c.post("/api/v1/auth/enroll/start").status_code == 409
