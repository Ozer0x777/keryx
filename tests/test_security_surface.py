"""Surface d'attaque : garde-fous génériques sur TOUTES les routes de l'API, découvertes automatiquement.
Un nouvel endpoint oublié sans authentification, sans CSRF ou sans contrôle de rôle fait échouer ces tests.
(Auto-contrôle : ne remplace pas un test d'intrusion.)  [ASVS 5.0 chap. 4, 7 ; PDIS IV.3.8, IV.3.9]"""
import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login

# Routes volontairement accessibles sans session (justification en commentaire) :
PUBLIC = {
    "/healthz",                               # supervision
    "/api/v1/auth/login", "/api/v1/auth/totp",  # authentification (étapes 1 et 2, session intermédiaire)
    "/api/v1/auth/providers",                 # liste des fournisseurs SSO (noms et libellés)
    "/api/v1/auth/enroll/start", "/api/v1/auth/enroll/finish",   # session « mot de passe » requise (contrôlée dans la route)
    "/api/v1/auth/webauthn/begin", "/api/v1/auth/webauthn/finish",
    "/api/v1/auth/oidc/{name}/start", "/api/v1/auth/oidc/{name}/callback",
    "/api/v1/auth/oidc/{name}/backchannel-logout",   # appel de serveur à serveur du fournisseur : jeton signé vérifié
    "/api/v1/ingest/wazuh",                   # clé d'API
    "/api/openapi.json",
}


def routes(app):
    for r in app.routes:
        if isinstance(r, APIRoute) and r.path.startswith(("/api/", "/healthz")):
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                yield m, r.path


def fill(path):
    return re.sub(r"\{[^}]+\}", "x", path)


def test_toute_route_non_publique_exige_une_authentification(app, db, world):
    c = TestClient(app)
    leaks = []
    for method, path in routes(app):
        if path in PUBLIC:
            continue
        r = c.request(method, fill(path), json={} if method != "GET" else None)
        if r.status_code not in (401, 403):
            leaks.append(f"{method} {path} → {r.status_code}")
    assert not leaks, "Routes accessibles sans authentification : " + "; ".join(leaks)
    assert len(list(routes(app))) > 90      # la découverte automatique a bien vu l'ensemble de l'API


def test_les_routes_publiques_ne_donnent_rien_sans_identifiants(app, db, world):
    c = TestClient(app)
    for path in ("/api/v1/ingest/wazuh",):
        assert c.post(path, json={}).status_code == 401
    assert c.post("/api/v1/auth/totp", json={"code": "123456"}).status_code == 401
    assert c.post("/api/v1/auth/enroll/start", json={"activation_code": "x" * 12}).status_code == 401
    assert c.post("/api/v1/auth/webauthn/begin").status_code == 401
    assert c.get("/api/v1/auth/oidc/inconnu/start", follow_redirects=False).status_code == 404
    assert c.get("/api/v1/auth/providers").json()["items"] == []


def test_toute_route_qui_modifie_exige_le_jeton_csrf(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    c = login(app, db, "manager")
    c.headers.pop("X-CSRF-Token")                     # session valide, sans jeton CSRF
    missing = []
    for method, path in routes(app):
        if method == "GET" or path in PUBLIC:
            continue
        r = c.request(method, fill(path).replace("/x/", "/ACME-1/", 1) if "{ref}" in path else fill(path), json={})
        if r.status_code != 403:
            missing.append(f"{method} {path} → {r.status_code}")
    assert not missing, "Routes qui modifient sans contrôle CSRF : " + "; ".join(missing)


ADMIN_ONLY = lambda p: p.startswith("/api/v1/admin/")


@pytest.mark.parametrize("who", ["analyst_acme", "client_acme", "manager"])
def test_routes_d_administration_interdites_aux_autres_roles(app, db, world, who):
    c = login(app, db, who)
    wrong = []
    for method, path in routes(app):
        if not ADMIN_ONLY(path):
            continue
        r = c.request(method, fill(path), json={})
        if r.status_code != 403:
            wrong.append(f"{method} {path} → {r.status_code}")
    assert not wrong, f"{who} atteint des routes d'administration : " + "; ".join(wrong)


def test_en_tetes_de_securite_et_cookies(app, db, world):
    c = TestClient(app)
    for path in ("/healthz", "/api/v1/auth/providers", "/connexion"):
        r = c.get(path)
        assert r.headers["x-content-type-options"] == "nosniff", path
        assert r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer", path
        assert "max-age=31536000" in r.headers["strict-transport-security"], path
        csp = r.headers["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "object-src 'none'" in csp, path
    assert c.get("/api/v1/auth/providers").headers["cache-control"] == "no-store"
    r = c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": "correct-horse-battery-staple"})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite" in cookie and "path=/" in cookie


def test_erreurs_sans_fuite_d_information(app, db, world):
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", content=b"{pas du json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422 and "Traceback" not in r.text and "File \"" not in r.text
    r = c.get("/api/v1/tickets/%00%27%22%3Cscript%3E")
    assert r.status_code in (401, 403, 404, 422) and "<script>" not in r.text
    u1 = c.post("/api/v1/auth/login", json={"username": "analyst_acme", "password": "faux"}).json()
    u2 = c.post("/api/v1/auth/login", json={"username": "inexistant-xyz", "password": "faux"}).json()
    assert u1 == u2                                    # même réponse : pas d'énumération des comptes
