"""WebAuthn : chemins de refus et cloisonnement (le parcours complet est dans e2e/scenarios/50-webauthn.mjs,
avec l'authentificateur virtuel de Chrome). [W3C WebAuthn ; ASVS 5.0 chap. 6]"""
from fastapi.testclient import TestClient
from sqlalchemy import select

from keryx.models import User, WebAuthnCredential

from .conftest import PASSWORD, login


def fake_key(db, user, name="clé", cid="Y3JlZC0x"):
    db.add(WebAuthnCredential(user_id=user.id, credential_id=cid, public_key="AAAA", sign_count=0, name=name))
    db.commit()


def test_enregistrement_exige_le_mot_de_passe_et_une_session_complete(app, db, world):
    assert TestClient(app).post("/api/v1/me/webauthn/register/begin", json={"password": PASSWORD}).status_code == 401
    c = login(app, db, "analyst_acme")
    assert c.post("/api/v1/me/webauthn/register/begin", json={"password": "faux"}).status_code == 403
    opts = c.post("/api/v1/me/webauthn/register/begin", json={"password": PASSWORD}).json()
    assert opts["rp"]["id"] == "keryx.local" and opts["user"]["name"] == "analyst_acme" and len(opts["challenge"]) >= 20
    assert opts["authenticatorSelection"]["residentKey"] == "discouraged"
    # Finir sans défi valide : refusé, le défi est à usage unique
    bad = c.post("/api/v1/me/webauthn/register/finish", json={"credential": {"id": "x", "rawId": "x", "type": "public-key", "response": {}}, "name": "k"})
    assert bad.status_code == 422
    assert c.post("/api/v1/me/webauthn/register/finish", json={"credential": {}, "name": "k"}).status_code == 409


def test_connexion_par_cle_refus_et_verrouillage(app, db, world):
    user = world["users"]["analyst_acme"]
    fake_key(db, user)
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD})
    assert r.json() == {"next": "totp", "webauthn": True}                      # le client propose la clé
    assert TestClient(app).post("/api/v1/auth/webauthn/begin").status_code == 401   # pas de session « mot de passe »
    opts = c.post("/api/v1/auth/webauthn/begin").json()
    assert opts["allowCredentials"][0]["id"] == "Y3JlZC0x" and opts["rpId"] == "keryx.local"
    forged = {"id": "Y3JlZC0x", "rawId": "Y3JlZC0x", "type": "public-key",
              "response": {"clientDataJSON": "e30", "authenticatorData": "AA", "signature": "AA"}}
    assert c.post("/api/v1/auth/webauthn/finish", json={"credential": forged}).status_code == 401
    assert c.get("/api/v1/tickets").status_code == 401                          # aucune session complète
    # Le défi est à usage unique ; les échecs comptent pour le verrouillage comme ceux du TOTP
    assert c.post("/api/v1/auth/webauthn/finish", json={"credential": forged}).status_code == 409
    db.expire_all()
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().failed_attempts == 1


def test_sans_cle_pas_de_proposition_et_begin_refuse(app, db, world):
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD}).json()["webauthn"] is False
    assert c.post("/api/v1/auth/webauthn/begin").status_code == 409


def test_liste_suppression_cloisonnees_et_reinitialisation_2fa(app, db, world):
    a, b = world["users"]["analyst_acme"], world["users"]["analyst_delta"]
    fake_key(db, a, "clé A", "QQ")
    fake_key(db, b, "clé B", "Qg")
    ca = login(app, db, "analyst_acme")
    items = ca.get("/api/v1/me/webauthn").json()["items"]
    assert [i["name"] for i in items] == ["clé A"]                              # on ne voit que ses propres clés
    other = db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.name == "clé B")).one()
    assert ca.delete(f"/api/v1/me/webauthn/{other.id}").status_code == 404      # ni ne supprime celles d'un autre
    # Une réinitialisation de la 2FA par l'Admin retire aussi les clés
    assert login(app, db, "admin").post("/api/v1/admin/users/analyst_acme/reset-2fa").status_code == 200
    db.expire_all()
    assert db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == a.id)).first() is None
    assert db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == b.id)).first() is not None
    assert ca.delete(f"/api/v1/me/webauthn/{items[0]['id']}").status_code in (401, 404)
