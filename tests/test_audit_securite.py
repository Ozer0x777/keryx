"""Correctifs de l'audit de sécurité du 2026-11-22 : un test par faille corrigée.

[ASVS 5.0 V2 validation, V4 limites de requêtes, V10 OAuth/OIDC ; RFC 9700 §4.7 ; ISO/IEC 27037 chaîne de possession ;
PDIS IV.3.8.g cloisonnement]"""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select

import keryx.routes_oidc as routes_oidc
from keryx.api import create_app
from keryx.models import Attachment, CustodyEvent, User
from keryx.oidc import load_providers
from keryx.sanitize import clean_html

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login
from .test_oidc import CLIENT, ISSUER, FakeIdp, begin, sso  # noqa: F401 - « sso » est une fixture

REG = {"description": "journal d'authentification", "method": "export manuel", "sensitivity": "TLP:AMBER"}
EXTREMES = ("0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59", "1969-12-31T23:59:59Z", "2999-01-01T00:00:00Z")


def zip_bytes(size: int = 0) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("auth.log", b"x" * max(1, size))
    return buf.getvalue()


def png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()


def upload(c, data=None, name="p.zip", collected_at="2026-11-20T10:00:00Z"):
    return c.post("/api/v1/tickets/ACME-1/attachments", data={**REG, "collected_at": collected_at},
                  files={"file": (name, data or zip_bytes(), "application/octet-stream")})


@pytest.fixture
def ticket(app, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    return "ACME-1"


# ---------------------------------------------------------------- 1. dates saisies bornées
def test_date_hors_limites_refusee_et_ticket_toujours_lisible(app, db, world, ticket):
    cl, an = login(app, db, "client_acme"), login(app, db, "analyst_acme")
    for d in EXTREMES:
        r = upload(cl, collected_at=d)
        assert r.status_code == 422 and "hors limites" in r.json()["detail"], (d, r.text)
        r = an.post("/api/v1/tickets/ACME-1/preuves-externes", json={
            "description": "disque", "collected_at": d, "method": "copie bit à bit", "sha256": "a" * 64, "location": "coffre 3"})
        assert r.status_code == 422, (d, r.text)
        assert an.put("/api/v1/tickets/ACME-1/synthese", json={"compromission_initiale": d}).status_code == 422, d
    assert db.scalars(select(Attachment)).all() == []                       # rien n'a été enregistré
    assert an.post("/api/v1/tickets/ACME-1/crisis", json={"active": True, "reason": "exfiltration"}).status_code == 200
    for d in EXTREMES[:3]:
        r = an.post("/api/v1/tickets/ACME-1/crisis/entries", json={"kind": "action", "body": "isoler", "due_at": d})
        assert r.status_code == 422, (d, r.text)
    assert an.post("/api/v1/tickets/ACME-1/crisis/entries",                 # une échéance future reste possible
                   json={"kind": "action", "body": "isoler", "due_at": "2027-06-01T08:00:00Z"}).status_code == 201
    assert upload(cl).status_code == 201                                     # une date normale passe
    assert an.get("/api/v1/tickets/ACME-1").status_code == 200 and cl.get("/api/v1/tickets/ACME-1").status_code == 200


# ---------------------------------------------------------------- 2. taille des corps de requête
def test_corps_trop_gros_refuse_avant_toute_lecture(app, db, world, ticket, settings):
    anon = TestClient(app)
    big_json = b'{"username":"' + b"a" * (settings.max_body_bytes + 10) + b'","password":"x"}'
    r = anon.post("/api/v1/auth/login", content=big_json, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.headers["content-type"] == "application/problem+json"
    # dépôt d'une pièce sans session : la borne ordinaire s'applique, pas celle des pièces
    assert upload(anon, zip_bytes(settings.max_body_bytes + 1000)).status_code == 413
    assert upload(anon).status_code == 401                                   # petit corps : refus habituel
    # envoi par morceaux, sans Content-Length : coupé pendant la lecture
    def chunks():
        for _ in range(settings.max_body_bytes // 65536 + 4):
            yield b"x" * 65536
    assert anon.post("/api/v1/auth/login", content=chunks(), headers={"Content-Type": "application/json"}).status_code == 413
    # avec une session ouverte, une pièce au-delà de la borne ordinaire est acceptée
    an = login(app, db, "analyst_acme")
    assert upload(an, zip_bytes(settings.max_body_bytes + 100_000)).status_code == 201
    # … mais une session ne lève pas la borne des autres routes
    r = an.post("/api/v1/tickets/ACME-1/comments", content=big_json, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


# ---------------------------------------------------------------- 3. chaîne de possession
def test_image_d_un_contenu_ne_peut_viser_que_le_contenu_d_une_piece():
    i = "01a2002b-ff98-72b1-b221-3b55cda07ffc"
    ok = f'<img src="/api/v1/attachments/{i}/content" alt="capture">'
    assert clean_html(ok) == ok
    for src in (f"/api/v1/attachments/{i}/content?motif=routine", f"/api/v1/attachments/{i}/custody", "/api/v1/tickets",
                "https://ailleurs.example/x.png", "//ailleurs.example/x.png", "data:image/png;base64,AAAA"):
        assert clean_html(f'<img src="{src}">') == "<img>", src


def test_telechargement_d_un_fichier_exige_le_jeton_csrf(app, db, world, ticket):
    cl, an = login(app, db, "client_acme"), login(app, db, "analyst_acme")
    fid = upload(cl).json()["id"]
    img = upload(an, png_bytes(), "capture.png").json()["id"]
    csrf = an.headers.pop("X-CSRF-Token")                # ce qu'envoie une balise <img> ou un lien : le cookie seul
    url = f"/api/v1/attachments/{fid}/content?motif=verification+de+routine"
    assert an.get(url).status_code == 403
    assert an.get(url, headers={"X-CSRF-Token": "faux"}).status_code == 403
    db.rollback()
    assert [c.action for c in db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == fid))] == ["depot"]
    assert an.get(f"/api/v1/attachments/{img}/content").status_code == 200     # une image s'affiche toujours en ligne
    assert an.get(url, headers={"X-CSRF-Token": csrf}).status_code == 200
    db.rollback()
    rows = db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == fid).order_by(CustodyEvent.ts)).all()
    assert [(c.actor, c.action) for c in rows] == [("client_acme", "depot"), ("analyst_acme", "telechargement")]


# ---------------------------------------------------------------- 4. SSO : rôles par fournisseur, état lié au navigateur
def test_roles_d_un_fournisseur_dans_la_configuration():
    base = {"name": "soc", "issuer": ISSUER, "client_id": CLIENT}
    assert load_providers(json.dumps([base]), False)["soc"].roles == ("manager", "analyst", "client")   # jamais admin par défaut
    assert load_providers(json.dumps([{**base, "roles": ["client"]}]), False)["soc"].roles == ("client",)
    for bad in ([], ["root"], "client"):
        with pytest.raises(RuntimeError):
            load_providers(json.dumps([{**base, "roles": bad}]), False)


def callback(c, q, code="c1"):
    return c.get("/api/v1/auth/oidc/soc/callback", params={"code": code, "state": q["state"][0]}, follow_redirects=False)


def test_un_fournisseur_ne_lie_pas_un_compte_admin(sso, db, world):
    admin = world["users"]["admin"]
    admin.email = "admin@soc.example"
    db.commit()
    FakeIdp.claims = {"preferred_username": "admin", "email": "admin@soc.example", "email_verified": True, "sub": "sub-admin"}
    c = TestClient(sso)
    assert callback(c, begin(c)).headers["location"] == "/connexion?sso_error=inconnu"
    db.expire_all()
    assert db.scalars(select(User).where(User.username == "admin")).one().oidc_sub is None
    assert c.get("/api/v1/me").status_code == 401


def test_fournisseur_restreint_aux_clients_et_role_recontrole_a_chaque_connexion(settings, db, world, monkeypatch):
    monkeypatch.setattr(routes_oidc, "Discovery", FakeIdp)
    FakeIdp.claims, FakeIdp.exchanged = {}, []
    settings.oidc_providers = json.dumps([{"name": "soc", "issuer": ISSUER, "client_id": CLIENT, "roles": ["client"]}])
    app = create_app(settings)
    world["users"]["analyst_acme"].email = "analyst@acme.example"
    world["users"]["client_acme"].email = "contact@acme.example"
    db.commit()
    c = TestClient(app)
    assert callback(c, begin(c)).headers["location"].endswith("inconnu")     # un analyste : hors du périmètre de ce realm
    db.expire_all()
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().oidc_sub is None
    FakeIdp.claims = {"preferred_username": "client_acme", "email": "contact@acme.example", "sub": "sub-client"}
    c = TestClient(app)
    assert callback(c, begin(c)).headers["location"] == "/" and c.get("/api/v1/me").json()["role"] == "client"
    # le compte lié devient analyste : ce fournisseur ne l'authentifie plus
    db.rollback()
    assert login(app, db, "admin").patch("/api/v1/admin/users/client_acme", json={"role": "analyst"}).status_code == 200
    c = TestClient(app)
    assert callback(c, begin(c)).headers["location"].endswith("inconnu") and c.get("/api/v1/me").status_code == 401


def test_etat_sso_lie_au_navigateur_qui_a_commence(sso, db):
    attacker, victim = TestClient(sso), TestClient(sso)
    q = begin(attacker)                                                       # l'attaquant commence, la victime termine
    assert callback(victim, q).headers["location"] == "/connexion?sso_error=etat"
    assert victim.get("/api/v1/me").status_code == 401
    r = sso and attacker.get("/api/v1/auth/oidc/soc/start", follow_redirects=False)
    cookie = r.headers["set-cookie"].lower()
    assert "keryx_sso=" in cookie and "httponly" in cookie and "samesite=lax" in cookie and "path=/api/v1/auth/oidc" in cookie


# ---------------------------------------------------------------- 5. contexte Wazuh : indexeur partagé
def test_deux_clients_sur_le_meme_indexeur_et_le_meme_motif_refuses(app, db, world):
    adm = login(app, db, "admin")
    cfg = {"wazuh_indexer_url": "https://indexeur.soc.example:9200", "wazuh_indexer_user": "lecture", "wazuh_indexer_password": "motdepasse-long"}
    assert adm.patch("/api/v1/admin/clients/ACME", json=cfg).status_code == 200
    r = adm.patch("/api/v1/admin/clients/DELTA", json=cfg)
    assert r.status_code == 422 and "ACME" in r.json()["detail"] and "motif d'index" in r.json()["detail"]
    assert adm.patch("/api/v1/admin/clients/DELTA", json={**cfg, "wazuh_index_pattern": "wazuh-alerts-delta-*"}).status_code == 200
    # et l'inverse : ACME ne peut pas reprendre le motif de DELTA
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_index_pattern": "wazuh-alerts-delta-*"}).status_code == 422


def test_corps_trop_gros_lu_et_jete_avant_le_413():
    """Le 413 part APRÈS la lecture du corps annoncé (jeté, non conservé) : sinon le client, ou le reverse proxy, voit
    une connexion réinitialisée pendant son envoi (502 constaté derrière Caddy) au lieu du refus."""
    import asyncio
    from keryx.bodylimit import BodyLimitMiddleware

    events = []

    async def app(scope, receive, send):   # jamais atteinte : le refus se fait avant l'application
        events.append("application")

    chunks = [{"type": "http.request", "body": b"x" * 1000, "more_body": True}] * 4 + [{"type": "http.request", "body": b"", "more_body": False}]
    queue = list(chunks)

    async def receive():
        events.append("lecture")
        return queue.pop(0)

    async def send(message):
        events.append(message["type"] + (f":{message['status']}" if "status" in message else ""))

    mw = BodyLimitMiddleware(app, default_limit=100, large=[], cookie_name="keryx_session", has_session=lambda t: False)
    scope = {"type": "http", "path": "/api/v1/auth/login", "headers": [(b"content-length", b"4000")]}
    asyncio.run(mw(scope, receive, send))
    assert events == ["lecture"] * 5 + ["http.response.start:413", "http.response.body"] and queue == []
