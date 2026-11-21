"""Authentification unique OIDC : contrôles du jeton, flux code + PKCE, liaison des comptes. [OIDC Core ; RFC 7636, 9700]"""
import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

import keryx.routes_oidc as routes_oidc
from keryx.api import create_app
from keryx.models import OidcFlow, User
from keryx.oidc import Discovery, OidcError, load_providers, verify_id_token

from .conftest import PASSWORD

ISSUER, CLIENT = "https://idp.example/realms/soc", "keryx"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(RSAAlgorithm.to_jwk(KEY.public_key())), "kid": "k1", "use": "sig", "alg": "RS256"}


def token(nonce="n1", key=KEY, alg="RS256", kid="k1", **over):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": CLIENT, "sub": "sub-1", "exp": now + 300, "iat": now, "nonce": nonce,
              "preferred_username": "analyst_acme", "email": "analyst@acme.example", "email_verified": True, **over}
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


keys = lambda force=False: [JWK]


def test_jeton_valide_puis_refus_de_chaque_defaut():
    assert verify_id_token(token(), keys, ISSUER, CLIENT, "n1")["sub"] == "sub-1"
    bad = [
        (token(aud="autre"), "invalide"), (token(iss="https://evil/realms/soc"), "invalide"),
        (token(exp=int(time.time()) - 600), "expiré"), (token(nonce="autre"), "Nonce"),
        (token(sub=None), "invalide"), (token(key=OTHER), "invalide"),          # signée par une autre clé
        (token(aud=[CLIENT, "x"]), "azp"),                                       # plusieurs destinataires sans azp
    ]
    for t, msg in bad:
        with pytest.raises(OidcError) as e:
            verify_id_token(t, keys, ISSUER, CLIENT, "n1")
        assert msg in str(e.value), (msg, str(e.value))
    # azp correct : accepté
    assert verify_id_token(token(aud=[CLIENT, "x"], azp=CLIENT), keys, ISSUER, CLIENT, "n1")
    # acr exigé
    with pytest.raises(OidcError):
        verify_id_token(token(), keys, ISSUER, CLIENT, "n1", required_acr="mfa")
    assert verify_id_token(token(acr="mfa"), keys, ISSUER, CLIENT, "n1", required_acr="mfa")


def test_algorithmes_dangereux_refuses():
    unsigned = jwt.encode({"iss": ISSUER, "aud": CLIENT, "sub": "x", "exp": int(time.time()) + 60, "iat": int(time.time()), "nonce": "n1"}, None, algorithm="none")
    with pytest.raises(OidcError, match="Algorithme"):
        verify_id_token(unsigned, keys, ISSUER, CLIENT, "n1")
    # Confusion de clé : HS256 « signé » avec la clé publique comme secret (PyJWT refuse de le fabriquer : on le forge à la main)
    import hmac
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64(json.dumps({"iss": ISSUER, "aud": CLIENT, "sub": "x", "exp": int(time.time()) + 60, "iat": int(time.time()), "nonce": "n1"}).encode())
    sig = b64(hmac.new(json.dumps(JWK).encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    with pytest.raises(OidcError, match="Algorithme"):
        verify_id_token(f"{head}.{body}.{sig}", keys, ISSUER, CLIENT, "n1")
    with pytest.raises(OidcError):
        verify_id_token("pas.un.jeton", keys, ISSUER, CLIENT, "n1")


def test_rotation_des_cles_rafraichit_une_fois():
    calls = []

    def get_keys(force=False):
        calls.append(force)
        return [JWK] if force else []
    assert verify_id_token(token(), get_keys, ISSUER, CLIENT, "n1")
    assert calls == [False, True]
    with pytest.raises(OidcError, match="inconnue"):
        verify_id_token(token(kid="nouveau"), lambda force=False: [JWK], ISSUER, CLIENT, "n1")


def test_http_refuse_sauf_essai_local():
    raw = json.dumps([{"name": "soc", "issuer": "http://idp/realms/soc", "client_id": "k"}])
    with pytest.raises(RuntimeError, match="HTTPS"):
        load_providers(raw, allow_http=False)
    assert "soc" in load_providers(raw, allow_http=True)
    with pytest.raises(RuntimeError):
        load_providers("pas du json", False)
    assert load_providers(None, False) == {}


# ----------------------------------------------------------------------------- flux complet avec un fournisseur simulé
class FakeIdp(Discovery):
    claims: dict = {}
    exchanged: list = []

    def meta(self):
        return {"authorization_endpoint": "https://idp.example/auth", "token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/jwks",
                "end_session_endpoint": "https://idp.example/logout"}

    def keys(self, force=False):
        return [JWK]

    def exchange(self, code, redirect_uri, verifier):
        FakeIdp.exchanged.append((code, redirect_uri, verifier))
        if code == "refuse":
            raise OidcError("Le fournisseur d'identité a refusé la connexion.")
        return token(nonce=FakeIdp.nonce, **FakeIdp.claims)


@pytest.fixture
def sso(settings, db, world, monkeypatch):
    monkeypatch.setattr(routes_oidc, "Discovery", FakeIdp)
    FakeIdp.claims, FakeIdp.exchanged = {}, []
    settings.oidc_providers = json.dumps([{"name": "soc", "label": "Compte SOC", "issuer": ISSUER, "client_id": CLIENT}])
    app = create_app(settings)
    user = world["users"]["analyst_acme"]
    user.email = "analyst@acme.example"
    db.commit()
    return app


def begin(c):
    r = c.get("/api/v1/auth/oidc/soc/start", follow_redirects=False)
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    FakeIdp.nonce = q["nonce"][0]
    return q


def test_flux_complet_liaison_puis_connexion_par_sub(sso, db, world):
    c = TestClient(sso)
    assert c.get("/api/v1/auth/providers").json()["items"] == [{"name": "soc", "label": "Compte SOC"}]
    q = begin(c)
    assert q["code_challenge_method"] == ["S256"] and q["response_type"] == ["code"] and q["scope"] == ["openid profile email"]
    r = c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c1", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert c.get("/api/v1/me").json()["username"] == "analyst_acme"
    assert c.get("/api/v1/me").json()["sso"] is True                     # session SSO : l'interface n'annonce pas « 2FA active »
    # PKCE : le vérificateur transmis au jeton correspond au défi annoncé
    verifier = FakeIdp.exchanged[0][2]
    assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == q["code_challenge"][0]
    assert FakeIdp.exchanged[0][1] == "https://keryx.local/api/v1/auth/oidc/soc/callback"
    db.expire_all()
    u = db.scalars(select(User).where(User.username == "analyst_acme")).one()
    assert u.oidc_sub == "sub-1" and u.oidc_issuer == ISSUER
    # Deuxième connexion : reconnu par « sub » seul, même si le courriel a changé
    FakeIdp.claims = {"email": "autre@ailleurs.example", "email_verified": False}
    c2 = TestClient(sso)
    q2 = begin(c2)
    assert c2.get("/api/v1/auth/oidc/soc/callback", params={"code": "c2", "state": q2["state"][0]}, follow_redirects=False).headers["location"] == "/"
    assert c2.get("/api/v1/me").status_code == 200


def test_etat_a_usage_unique_inconnu_ou_expire(sso, db):
    c = TestClient(sso)
    q = begin(c)
    st = q["state"][0]
    assert c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": st}, follow_redirects=False).headers["location"] == "/"
    again = c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": st}, follow_redirects=False)
    assert again.headers["location"] == "/connexion?sso_error=etat"                              # rejeu refusé
    assert c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": "inconnu"}, follow_redirects=False).headers["location"].endswith("etat")
    q = begin(TestClient(sso))
    from datetime import timedelta
    from keryx.ids import utcnow
    flow = db.scalars(select(OidcFlow)).one()
    flow.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert TestClient(sso).get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False).headers["location"].endswith("etat")
    assert c.get("/api/v1/auth/oidc/soc/callback", params={"error": "access_denied"}, follow_redirects=False).headers["location"].endswith("refuse")
    assert c.get("/api/v1/auth/oidc/inconnu/start", follow_redirects=False).status_code == 404


def test_refus_nonce_courriel_compte_inconnu_inactif(sso, db, world):
    def attempt(**claims):
        c = TestClient(sso)
        q = begin(c)
        FakeIdp.claims = claims
        r = c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
        return r.headers["location"], c.get("/api/v1/me").status_code
    # courriel non vérifié, ou différent : pas de liaison (empêche la prise de compte par homonymie d'identifiant)
    assert attempt(email_verified=False) == ("/connexion?sso_error=liaison", 401)
    assert attempt(email="pirate@evil.example") == ("/connexion?sso_error=liaison", 401)
    assert attempt(preferred_username="personne") == ("/connexion?sso_error=inconnu", 401)
    FakeIdp.nonce_override = None
    c = TestClient(sso); q = begin(c); FakeIdp.nonce = "mauvais-nonce"
    r = c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    assert r.headers["location"].endswith("jeton") and c.get("/api/v1/me").status_code == 401
    c = TestClient(sso); q = begin(c)
    r = c.get("/api/v1/auth/oidc/soc/callback", params={"code": "refuse", "state": q["state"][0]}, follow_redirects=False)
    assert r.headers["location"].endswith("jeton")
    # compte déjà lié à une autre identité : refusé même avec le bon courriel
    u = world["users"]["analyst_acme"]
    u.oidc_issuer, u.oidc_sub = ISSUER, "autre-sub"
    db.commit()
    assert attempt() == ("/connexion?sso_error=inconnu", 401)
    u.oidc_sub, u.active = "sub-1", False
    db.commit()
    assert attempt() == ("/connexion?sso_error=inconnu", 401)
    from datetime import timedelta
    from keryx.ids import utcnow
    u.active, u.locked_until = True, utcnow() + timedelta(minutes=5)
    db.commit()
    assert attempt() == ("/connexion?sso_error=verrouille", 401)


def test_sso_obligatoire_ne_laisse_que_ladmin_en_local(settings, db, world, monkeypatch):
    monkeypatch.setattr(routes_oidc, "Discovery", FakeIdp)
    settings.oidc_providers = json.dumps([{"name": "soc", "issuer": ISSUER, "client_id": CLIENT}])
    settings.oidc_enforce = True
    app = create_app(settings)
    assert TestClient(app).get("/api/v1/auth/providers").json()["local_login_enabled"] is False
    r = TestClient(app).post("/api/v1/auth/login", json={"username": "analyst_acme", "password": PASSWORD})
    assert r.status_code == 403 and "SSO" in r.json()["detail"]
    assert TestClient(app).post("/api/v1/auth/login", json={"username": "analyst_acme", "password": "faux"}).status_code == 401   # pas d'énumération
    assert TestClient(app).post("/api/v1/auth/login", json={"username": "admin", "password": PASSWORD}).json()["next"] == "totp"   # accès de secours


def test_delier_le_sso_reserve_a_ladmin(sso, db, world):
    from .conftest import login
    u = world["users"]["analyst_acme"]
    u.oidc_issuer, u.oidc_sub = ISSUER, "sub-1"
    db.commit()
    assert login(sso, db, "analyst_delta").post("/api/v1/admin/users/analyst_acme/unlink-sso").status_code == 403
    adm = login(sso, db, "admin")
    assert adm.get("/api/v1/me").json()["sso"] is False                 # session locale (mot de passe + second facteur)
    assert adm.post("/api/v1/admin/users/analyst_acme/unlink-sso").status_code == 200
    db.expire_all()
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().oidc_sub is None


def test_deconnexion_unique(sso, db, world):
    c = TestClient(sso)
    q = begin(c)
    c.get("/api/v1/auth/oidc/soc/callback", params={"code": "c", "state": q["state"][0]}, follow_redirects=False)
    c.headers["X-CSRF-Token"] = c.cookies.get("keryx_csrf")
    from keryx.models import Session
    row = db.scalars(select(Session).where(Session.stage == "full")).one()
    assert row.sso_provider == "soc" and row.sso_id_token.startswith("v1:") and "eyJ" not in row.sso_id_token   # jeton conservé chiffré
    r = c.post("/api/v1/auth/logout")
    url = urlparse(r.json()["redirect"])
    qs = parse_qs(url.query)
    assert url.netloc == "idp.example" and url.path == "/logout"
    assert qs["post_logout_redirect_uri"] == ["https://keryx.local/connexion"] and qs["client_id"] == [CLIENT]
    assert jwt.decode(qs["id_token_hint"][0], options={"verify_signature": False})["sub"] == "sub-1"   # indice : le jeton reçu
    assert c.get("/api/v1/me").status_code == 401
    db.rollback()   # fin du snapshot de lecture de ce test
    assert db.scalars(select(Session).where(Session.stage == "full")).first() is None
    # Une session locale (mot de passe + TOTP) ne redirige nulle part
    from .conftest import login
    local = login(sso, db, "manager")
    assert local.post("/api/v1/auth/logout").json() == {"status": "ok", "redirect": None}
