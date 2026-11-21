"""Charges d'injection SQL : traitées comme de simples valeurs, jamais exécutées.
Né d'un constat de l'analyse dynamique OWASP ZAP (voir docs/homologation/dast-zap.md) : une injection « temporelle »
signalée sur bulk-assign était un faux positif ; ce test le démontre et protège contre une vraie régression."""
import pytest
from sqlalchemy import select

from keryx.models import Ticket, User

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login

PAYLOADS = ["' OR '1'='1", "x'; DROP TABLE users; --", "\" OR 1=1 --", "case randomblob(1000000) when not null then 1 else 1 end ",
            "') UNION SELECT username, password_hash FROM users --", "1; ATTACH DATABASE '/tmp/x' AS y; --", "%' AND 1=2 UNION SELECT 1 --"]


def probe(c, method, path, **kw):
    r = c.request(method, path, **kw)
    return r.status_code, r.text


@pytest.mark.parametrize("payload", PAYLOADS)
def test_les_parametres_texte_ne_sont_jamais_interpretes(app, db, world, alert, payload):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    m = login(app, db, "manager")
    benign = "valeur-banale-xyz"
    calls = [
        ("POST", "/api/v1/tickets/bulk-assign", lambda v: dict(json={"refs": ["ACME-1"], "username": v})),
        ("GET", "/api/v1/tickets", lambda v: dict(params={"q": v})),
        ("GET", "/api/v1/tickets", lambda v: dict(params={"assignee": v})),
        ("GET", "/api/v1/tickets", lambda v: dict(params={"status": v})),
        ("GET", "/api/v1/tickets", lambda v: dict(params={"client": v})),
        ("GET", "/api/v1/audit/entries", lambda v: dict(params={"actor": v})),
        ("GET", "/api/v1/audit/entries", lambda v: dict(params={"action": v})),
        ("GET", "/api/v1/audit/entries", lambda v: dict(params={"object_id": v})),
        ("GET", "/api/v1/registre", lambda v: dict(params={"client": v})),
        ("GET", "/api/v1/mitre/techniques", lambda v: dict(params={"q": v})),
        ("GET", f"/api/v1/tickets/{'ACME-1'}/links", lambda v: {}),
        ("POST", "/api/v1/tickets/ACME-1/links", lambda v: dict(json={"ref": v, "kind": "lie"})),
        ("POST", "/api/v1/tickets/ACME-1/assign", lambda v: dict(json={"username": v})),
    ]
    for method, path, build in calls:
        got = probe(m, method, path, **build(payload))
        ref = probe(m, method, path, **build(benign))
        assert got[0] < 500 and ref[0] < 500, (path, got)
        # même traitement qu'une valeur banale ; seule différence admise : un refus de validation (longueur maximale du champ)
        assert got[0] == ref[0] or got[0] == 422, (path, payload, got[0], ref[0])
        assert "password_hash" not in got[1] and "argon2" not in got[1].lower()
    # Connexion : identifiant piégé = simple échec, même réponse qu'un identifiant inconnu
    from fastapi.testclient import TestClient
    c = TestClient(app)
    a = c.post("/api/v1/auth/login", json={"username": payload, "password": "x"})
    b = c.post("/api/v1/auth/login", json={"username": benign, "password": "x"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    db.rollback()
    assert db.scalars(select(User)).all() and db.scalars(select(Ticket)).all()    # rien n'a été supprimé ni modifié


def test_chemins_de_fichiers_et_dotfiles_recoivent_un_404(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    for path in ("/.git/config", "/.env", "/.hg", "/BitKeeper", "/._darcs", "/backup.zip", "/admin.php", "/x/y/.svn/entries", "/sitemap.xml"):
        assert c.get(path).status_code == 404, path
    assert c.get("/healthz").status_code == 200
