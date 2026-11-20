"""Administration dans l'interface. [PDIS IV.3.4.b, IV.3.9.d à h ; PRIS IV.3.n, o]"""
import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from keryx.models import Session, User

from .conftest import ALERT_SSH_BRUTEFORCE, PASSWORD, ingest, login


def test_routes_reservees_a_ladmin(app, db, world):
    for who in ("analyst_acme", "client_acme", "manager"):
        c = login(app, db, who)
        for path in ("/admin/users", "/admin/clients", "/admin/api-keys", "/admin/system"):
            assert c.get(f"/api/v1{path}").status_code == 403, (who, path)


def test_creation_compte_et_regles_de_role(app, db, world):
    a = login(app, db, "admin")
    ok = a.post("/api/v1/admin/users", json={"username": "nouvel.analyste", "display_name": "N. A.", "role": "analyst",
                                              "clients": ["ACME"], "password": "un-mot-de-passe-solide"})
    assert ok.status_code == 201, ok.text
    body = ok.json()
    # L'Admin ne reçoit AUCUN secret : le titulaire enrôle lui-même sa 2FA à sa première connexion.
    assert body["enrolled"] is False and not any(k in body for k in ("totp_uri", "totp_secret", "recovery_codes"))
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"username": "nouvel.analyste", "password": "un-mot-de-passe-solide"})
    assert r.status_code == 200 and r.json()["next"] == "enroll"
    # Règles : admin sans client, client avec exactement un client, analyste avec au moins un client
    bad = [dict(role="admin", clients=["ACME"]), dict(role="client", clients=["ACME", "DELTA"]),
           dict(role="analyst", clients=[]), dict(role="inconnu", clients=["ACME"]), dict(role="analyst", clients=["NOPE"])]
    for i, extra in enumerate(bad):
        r = a.post("/api/v1/admin/users", json={"username": f"x.user{i}", "display_name": "X", "password": "un-mot-de-passe-solide", **extra})
        assert r.status_code == 422, (extra, r.text)
    dup = a.post("/api/v1/admin/users", json={"username": "nouvel.analyste", "display_name": "N", "role": "analyst",
                                               "clients": ["ACME"], "password": "un-mot-de-passe-solide"})
    assert dup.status_code == 409


def test_modification_ferme_les_sessions_et_protege_son_propre_compte(app, db, world):
    a = login(app, db, "admin")
    login(app, db, "analyst_acme")
    assert db.scalars(select(Session).where(Session.user_id == world["users"]["analyst_acme"].id)).first()
    r = a.patch("/api/v1/admin/users/analyst_acme", json={"clients": ["ACME", "DELTA"]})
    assert r.status_code == 200 and r.json()["clients"] == ["ACME", "DELTA"]
    db.rollback()
    assert db.scalars(select(Session).where(Session.user_id == world["users"]["analyst_acme"].id)).first() is None
    assert a.patch("/api/v1/admin/users/admin", json={"active": False}).status_code == 409
    assert a.patch("/api/v1/admin/users/analyst_acme", json={"active": False}).json()["active"] is False


def test_reinitialisation_2fa_tracee(app, db, world):
    a = login(app, db, "admin")
    r = a.post("/api/v1/admin/users/client_acme/reset-2fa")
    assert r.status_code == 200 and r.json()["enrolled"] is False and "totp_secret" not in r.json()
    db.rollback()
    db.refresh(world["users"]["client_acme"])
    assert world["users"]["client_acme"].totp_secret == "" and world["users"]["client_acme"].recovery_codes == []
    assert a.get("/api/v1/audit/verify").json()["chain_ok"] is True


def test_cles_api_creation_rotation_revocation(app, db, world, alert):
    a = login(app, db, "admin")
    k = a.post("/api/v1/admin/api-keys", json={"client": "ACME", "name": "wazuh-2"}).json()
    assert k["key"].startswith("kx_") and k["silent"] is False  # neuve, jamais utilisée : le délai court depuis sa création
    assert ingest(app, k["key"], alert(ALERT_SSH_BRUTEFORCE)).status_code == 201
    rows = a.get("/api/v1/admin/api-keys").json()["items"]
    used = next(x for x in rows if x["id"] == k["id"])
    assert used["last_used_at"] and used["silent"] is False
    new = a.post(f"/api/v1/admin/api-keys/{k['id']}/rotate").json()
    assert ingest(app, k["key"], alert(ALERT_SSH_BRUTEFORCE)).status_code == 401  # ancienne clé révoquée
    assert ingest(app, new["key"], alert(ALERT_SSH_BRUTEFORCE)).status_code in (200, 201)
    assert a.post(f"/api/v1/admin/api-keys/{new['id']}/revoke").json()["revoked"] is True


def test_client_parametrage_valide(app, db, world):
    a = login(app, db, "admin")
    assert a.post("/api/v1/admin/clients", json={"key": "nova", "name": "Nova SA"}).status_code == 201
    r = a.patch("/api/v1/admin/clients/NOVA", json={"contact_emails": ["soc@nova.example", "pas-un-mail"],
                                                     "retention_months": 12,
                                                     "sla": {"Critique": {"qualification": 1, "resolution": 8}}})
    assert r.status_code == 200 and r.json()["contact_emails"] == ["soc@nova.example"]
    assert a.patch("/api/v1/admin/clients/NOVA", json={"retention_months": 2}).status_code == 422  # < 6 mois
    assert a.patch("/api/v1/admin/clients/NOVA", json={"severity_grid": {"limites": {}}}).status_code == 422
    assert a.patch("/api/v1/admin/clients/NOVA", json={"sla": {"Inconnue": {"qualification": 1}}}).status_code == 422


def test_mitre_manager_et_admin(app, db, world):
    m = login(app, db, "manager")
    r = m.post("/api/v1/mitre/mappings", json={"technique": "T1078", "name": "Valid Accounts", "tactic": "Persistence",
                                               "rule_group": "authentication_success"})
    assert r.status_code == 201
    assert m.post("/api/v1/mitre/mappings", json={"technique": "bad", "rule_id": "1"}).status_code == 422
    assert m.post("/api/v1/mitre/mappings", json={"technique": "T1078"}).status_code == 422  # ni règle ni groupe
    assert any(x["technique"] == "T1078" for x in m.get("/api/v1/mitre/mappings").json()["items"])
    assert m.delete(f"/api/v1/mitre/mappings/{r.json()['id']}").status_code == 200
    assert login(app, db, "analyst_acme").get("/api/v1/mitre/mappings").status_code == 403


def test_profil_mot_de_passe_codes_et_sessions(app, db, world):
    c = login(app, db, "analyst_acme")
    other = login(app, db, "analyst_acme")  # deuxième session
    assert c.post("/api/v1/me/password", json={"current": "faux", "new": "nouveau-mot-de-passe-1"}).status_code == 403
    assert c.post("/api/v1/me/password", json={"current": PASSWORD, "new": "court"}).status_code == 422
    assert c.post("/api/v1/me/password", json={"current": PASSWORD, "new": "nouveau-mot-de-passe-1"}).status_code == 200
    assert other.get("/api/v1/me").status_code == 401  # l'autre session est fermée
    assert c.get("/api/v1/me").status_code == 200       # la courante est conservée
    codes = c.post("/api/v1/me/recovery-codes", json={"password": "nouveau-mot-de-passe-1"}).json()["recovery_codes"]
    assert len(codes) == 10
    assert c.post("/api/v1/me/recovery-codes", json={"password": "faux"}).status_code == 403
    sessions = c.get("/api/v1/me/sessions").json()["items"]
    assert len(sessions) == 1
    assert c.delete(f"/api/v1/me/sessions/{sessions[0]['id']}").status_code == 200
    assert c.get("/api/v1/me").status_code == 401


def test_etat_du_systeme(app, db, world):
    from datetime import timedelta
    from keryx.ids import utcnow
    from keryx.models import ApiKey
    adm = login(app, db, "admin")
    s = adm.get("/api/v1/admin/system").json()
    assert s["database"] == "ok" and s["smtp"] == "non configuré" and s["clamav"] == "non configuré"
    assert s["disk_free_mb"] > 0 and s["silent_sources"] == 0  # clés neuves : pas encore de silence anormal
    for k in db.scalars(select(ApiKey)):
        k.created_at = utcnow() - timedelta(days=3)
    db.commit()
    assert adm.get("/api/v1/admin/system").json()["silent_sources"] == 2  # deux clés anciennes, aucune utilisée
