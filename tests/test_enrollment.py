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
    return r.json()["enrollment_code"]


def test_parcours_complet_d_enrolement(app, db, world):
    act = create(app, db, world)
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "nouveau", "password": TEMP}).json()["next"] == "enroll"
    # Tant que l'enrôlement n'est pas fait : ni TOTP, ni accès
    assert c.post("/api/v1/auth/totp", json={"code": "123456"}).status_code == 401
    assert c.get("/api/v1/tickets").status_code == 401
    assert c.post("/api/v1/auth/enroll/finish", json={"code": "123456", "new_password": "un-autre-mot-de-passe"}).status_code == 409  # pas démarré
    # Le mot de passe temporaire seul ne suffit pas : code d'activation requis
    assert c.post("/api/v1/auth/enroll/start", json={"activation_code": "mauvais-code-xx"}).status_code == 401
    start = c.post("/api/v1/auth/enroll/start", json={"activation_code": act}).json()
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
    act = create(app, db, world, "suivant")
    c = TestClient(app)
    c.post("/api/v1/auth/login", json={"username": "suivant", "password": TEMP})
    start = c.post("/api/v1/auth/enroll/start", json={"activation_code": act}).json()
    code = pyotp.TOTP(start["totp_secret"]).now()
    done = c.post("/api/v1/auth/enroll/finish", json={"code": code, "new_password": "un-autre-mot-de-passe"}).json()
    c2 = TestClient(app)
    assert c2.post("/api/v1/auth/login", json={"username": "suivant", "password": "un-autre-mot-de-passe"}).json()["next"] == "totp"
    assert c2.post("/api/v1/auth/enroll/start", json={"activation_code": act}).status_code == 409          # déjà enrôlé : le secret ne peut pas être écrasé
    assert c2.post("/api/v1/auth/totp", json={"code": code}).status_code == 401  # le code d'enrôlement ne rejoue pas
    assert c2.post("/api/v1/auth/totp", json={"recovery_code": done["recovery_codes"][0]}).status_code == 200


def test_reinitialisation_2fa_impose_un_nouvel_enrolement(app, db, world):
    adm = login(app, db, "admin")
    old = login(app, db, "analyst_acme")
    assert old.get("/api/v1/me").status_code == 200
    r2 = adm.post("/api/v1/admin/users/analyst_acme/reset-2fa")
    assert r2.status_code == 200
    act = r2.json()["enrollment_code"]
    assert old.get("/api/v1/me").status_code == 401                       # sessions fermées
    act = adm.post("/api/v1/admin/users/analyst_acme/reset-password", json={"password": TEMP}).json()["enrollment_code"]
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": TEMP}).json()["next"] == "enroll"
    start = c.post("/api/v1/auth/enroll/start", json={"activation_code": act}).json()
    r = c.post("/api/v1/auth/enroll/finish", json={"code": pyotp.TOTP(start["totp_secret"]).now(), "new_password": "mot-de-passe-definitif-9"})
    assert r.status_code == 200
    db.rollback()
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().enrolled is True


def test_enrolement_sans_session_ou_pour_un_autre_compte(app, db, world):
    c = TestClient(app)
    assert c.post("/api/v1/auth/enroll/start", json={"activation_code": "x" * 10}).status_code == 401
    assert c.post("/api/v1/auth/enroll/finish", json={"code": "123456", "new_password": "x" * 12}).status_code == 401
    # Un compte déjà enrôlé (rôle quelconque) ne peut pas relancer un enrôlement qui écraserait son secret
    c.post("/api/v1/auth/login", json={"username": "manager", "password": "correct-horse-battery-staple"})
    assert c.post("/api/v1/auth/enroll/start", json={"activation_code": "x" * 10}).status_code == 409


def test_premier_admin_cree_par_la_cli_avec_code_d_activation(app, db, settings, monkeypatch, capsys):
    """Installation : « keryx add-user … --activation » crée un compte à activer, comme l'interface le fait
    (aucun secret TOTP affiché dans le terminal, mot de passe temporaire à changer). [PDIS IV.3.9.d à h ; RFC 6238]"""
    from keryx.cli import main as cli_main
    monkeypatch.setenv("KERYX_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KERYX_SECRET_KEY", settings.secret_key)
    monkeypatch.setenv("KERYX_NEW_PASSWORD", TEMP)
    assert cli_main(["add-user", "admin", "Administrateur", "admin", "--activation"]) == 0
    out = capsys.readouterr().out
    assert "otpauth://" not in out and "Codes de secours" not in out          # rien d'autre que le code d'activation
    act = out.strip().splitlines()[-1].strip()
    assert len(act) >= 12 and "Code d'activation" in out
    u = db.scalars(select(User).where(User.username == "admin")).one()
    assert u.role == "admin" and not u.enrolled and u.totp_secret == "" and u.recovery_codes == []
    assert u.enroll_code_hash and act not in u.enroll_code_hash                 # seul le haché est en base
    db.rollback()
    # Relance de l'installateur : pas de doublon, pas de trace d'erreur, code de sortie 2
    assert cli_main(["add-user", "admin", "Administrateur", "admin", "--activation"]) == 2
    assert "existe déjà" in capsys.readouterr().err
    # Le titulaire active son compte : mot de passe temporaire + code, TOTP enrôlé dans le navigateur
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "admin", "password": TEMP}).json()["next"] == "enroll"
    assert c.post("/api/v1/auth/enroll/start", json={"activation_code": "mauvais-code-xx"}).status_code == 401
    start = c.post("/api/v1/auth/enroll/start", json={"activation_code": act}).json()
    code = pyotp.TOTP(start["totp_secret"]).now()
    done = c.post("/api/v1/auth/enroll/finish", json={"code": code, "new_password": "un-autre-mot-de-passe"})
    assert done.status_code == 200 and done.json()["role"] == "admin" and len(done.json()["recovery_codes"]) == 10
    assert TestClient(app).post("/api/v1/auth/login", json={"username": "admin", "password": TEMP}).status_code == 401


def test_add_user_sans_terminal_message_clair_et_mot_de_passe_sur_stdin(app, db, settings, monkeypatch, capsys):
    """Sans terminal ni KERYX_NEW_PASSWORD : erreur explicite (pas d'EOFError). --password-stdin lit l'entrée."""
    import io
    from keryx.cli import main as cli_main
    monkeypatch.setenv("KERYX_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KERYX_SECRET_KEY", settings.secret_key)
    monkeypatch.delenv("KERYX_NEW_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert cli_main(["add-user", "stdin1", "Test", "admin", "--activation"]) == 2
    err = capsys.readouterr().err
    assert "KERYX_NEW_PASSWORD" in err and "--password-stdin" in err
    monkeypatch.setattr("sys.stdin", io.StringIO(TEMP + "\n"))
    assert cli_main(["add-user", "stdin1", "Test", "admin", "--activation", "--password-stdin"]) == 0
    db.rollback()
    assert db.scalars(select(User).where(User.username == "stdin1")).one().role == "admin"
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert cli_main(["add-user", "stdin2", "Test", "admin", "--activation", "--password-stdin"]) == 2


def test_identifiant_de_connexion_sans_espaces_autour(app, db, settings, monkeypatch, capsys):
    from keryx.cli import main as cli_main
    monkeypatch.setenv("KERYX_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KERYX_SECRET_KEY", settings.secret_key)
    monkeypatch.setenv("KERYX_NEW_PASSWORD", TEMP)
    assert cli_main(["add-user", "espace", "Test", "admin", "--activation"]) == 0
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "  espace ", "password": TEMP}).json()["next"] == "enroll"
