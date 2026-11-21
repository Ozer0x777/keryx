"""Non-régression des correctifs de la troisième revue : cloisonnement des pièces insérées depuis l'éditeur, propositions
MITRE vues par l'Admin, favicon, classification ISI mal typée, SSO obligatoire et enrôlement local, limiteur partagé sur
SQLite, traçabilité (comptes, sauvegarde, lectures sensibles), cycle de vie des pièces, bornes de dates du journal,
réponse d'un client quand l'assigné est désactivé."""
import io
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select

import keryx.routes_oidc as routes_oidc
from keryx import attachments as att
from keryx.api import create_app
from keryx.cli import main as cli_main
from keryx.models import Attachment, AuditEntry, CustodyEvent, RateHit, User

from .conftest import ALERT_CRITICAL, ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, PASSWORD, SECRET_KEY, ingest, login
from .test_attachments import REGISTRY, zip_bytes
from .test_enrollment import TEMP, create as create_unenrolled
from .test_oidc import CLIENT, ISSUER, FakeIdp


def png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (30, 20), (10, 120, 200)).save(buf, format="PNG")
    return buf.getvalue()


def deposit(c, ref="ACME-1", data=None, name="capture.png", **extra):
    r = c.post(f"/api/v1/tickets/{ref}/attachments", data={**REGISTRY, **extra},
               files={"file": (name, data or png(), "application/octet-stream")})
    assert r.status_code == 201, r.text
    return r.json()


def actions(db, prefix=""):
    db.rollback()  # nouvel instantané de lecture
    return [e for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq)) if e.action.startswith(prefix)]


# ---------------------------------------------------------------- M1 : images insérées depuis l'éditeur
def test_image_d_editeur_visible_seulement_par_un_contenu_visible(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))            # ACME-2 : un autre ticket du même client
    a, c = login(app, db, "analyst_acme"), login(app, db, "client_acme")

    def img_html(i):
        return f'<p>voir</p><img src="/api/v1/attachments/{i}/content" alt="capture">'

    def client_sees(i):
        listed = i in [x["id"] for x in c.get("/api/v1/tickets/ACME-1").json()["attachments"]]
        served = c.get(f"/api/v1/attachments/{i}/content").status_code == 200
        assert listed == served
        return served

    # Déposée depuis l'éditeur : jamais visible au dépôt, même si la case « visible » était cochée à cet instant
    img = deposit(a, embedded="true", visible_client="true")
    assert img["visible_client"] is False and not client_sees(img["id"])
    # Commentaire interne : l'image reste interne
    r = a.post("/api/v1/tickets/ACME-1/comments", json={"body_html": img_html(img["id"]), "visible_client": False})
    assert r.status_code == 201 and img["id"] in r.json()["body_html"]
    assert not client_sees(img["id"])
    # Un client qui cite l'adresse d'une pièce interne ne la rend pas visible
    assert c.post("/api/v1/tickets/ACME-1/comments", json={"body_html": img_html(img["id"])}).status_code == 201
    assert not client_sees(img["id"])
    # Commentaire visible par le client : le serveur rend l'image visible, et le trace
    assert a.post("/api/v1/tickets/ACME-1/comments", json={"body_html": img_html(img["id"]), "visible_client": True}).status_code == 201
    assert client_sees(img["id"])
    db.rollback()
    assert "visible_client" in [e.action for e in db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == img["id"]))]
    assert any(e["action"] == "piece_jointe_visible" and e["details"]["id"] == img["id"]
               for e in a.get("/api/v1/tickets/ACME-1").json()["events"])
    # Description (lue par le client) : même règle à l'enregistrement
    img2 = deposit(a, embedded="true")
    assert not client_sees(img2["id"])
    assert a.put("/api/v1/tickets/ACME-1/body", json={"body_html": img_html(img2["id"])}).status_code == 200
    assert client_sees(img2["id"])
    # Jamais une pièce d'un autre ticket, ni une archive, ni par un simple renvoi dans un contenu visible
    other = deposit(a, ref="ACME-2", embedded="true")
    archive = deposit(a, data=zip_bytes(), name="journaux.zip")
    both = img_html(other["id"]) + img_html(archive["id"])
    assert a.post("/api/v1/tickets/ACME-1/comments", json={"body_html": both, "visible_client": True}).status_code == 201
    db.rollback()
    assert {x.id: x.visible_client for x in db.scalars(select(Attachment).where(Attachment.id.in_([other["id"], archive["id"]])))} \
        == {other["id"]: False, archive["id"]: False}
    assert c.get(f"/api/v1/attachments/{other['id']}/content").status_code == 404
    # Un dépôt du client (image insérée dans sa réponse) reste visible par lui
    assert deposit(c, embedded="true")["visible_client"] is True


# ---------------------------------------------------------------- M2 : propositions MITRE et rôle Admin
def test_propositions_mitre_sans_contenu_de_ticket_pour_l_admin(app, db, world, alert):
    a = login(app, db, "analyst_acme")
    for i in range(3):
        payload = alert(ALERT_NO_MITRE)
        payload["id"] = f"m{i}"
        payload["agent"]["id"] = f"00{i}"
        ingest(app, world["keys"]["ACME"], payload)
        a.post(f"/api/v1/tickets/ACME-{i + 1}/mitre", json={"techniques": ["T1110"]})
    r = login(app, db, "admin").get("/api/v1/mitre/suggestions")
    assert r.json()["items"] == [{"rule_id": "100200", "rule_description": None, "technique": "T1110", "count": 3,
                                  "name": "", "tactics": []}]
    assert "Custom" not in r.text and "authentication" not in r.text      # la description de règle vient des tickets
    assert login(app, db, "manager").get("/api/v1/mitre/suggestions").json()["items"][0]["rule_description"].startswith("Custom")


# ---------------------------------------------------------------- M3 : favicon
def test_favicon_servi_et_autres_fichiers_refuses(settings, tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>Keryx</title>")
    (dist / "favicon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
    (dist / "secret.svg").write_text("<svg/>")
    settings.web_dist = str(dist)
    c = TestClient(create_app(settings))
    r = c.get("/favicon.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml") and "<svg" in r.text
    assert r.headers["x-content-type-options"] == "nosniff"
    assert c.get("/secret.svg").status_code == 404 and c.get("/backup.zip").status_code == 404   # la règle générale tient
    assert c.get("/tickets").status_code == 200


def test_favicon_absent_404(app):
    assert TestClient(app).get("/favicon.svg").status_code == 404           # interface non construite


# ---------------------------------------------------------------- M4 : classification ISI mal typée
@pytest.mark.parametrize("body", [
    {"category": ["IEX"]}, {"category": {"a": 1}}, {"who_why": {"a": 1}}, {"what": [["unauthorized_access"]]},
    {"how": ["unauthorized_access"]}, {"how": {"x": 1}}, {"vulnerability": [{"a": 1}]}, {"asset": 5}, {"detail": ["x"]},
])
def test_classification_isi_mal_typee_422(app, db, world, alert, body):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    r = login(app, db, "analyst_acme").put("/api/v1/tickets/ACME-1/isi", json=body)
    assert r.status_code == 422, r.text


# ---------------------------------------------------------------- M5 : SSO obligatoire et enrôlement local
def test_sso_obligatoire_refuse_l_enrolement_local(settings, app, db, world, monkeypatch):
    code = create_unenrolled(app, db, world)                                # compte non Admin, pas encore enrôlé
    pending = TestClient(app)                                               # session « mot de passe » ouverte avant le passage au SSO
    assert pending.post("/api/v1/auth/login", json={"username": "nouveau", "password": TEMP}).json()["next"] == "enroll"
    monkeypatch.setattr(routes_oidc, "Discovery", FakeIdp)
    settings.oidc_providers = json.dumps([{"name": "soc", "issuer": ISSUER, "client_id": CLIENT}])
    settings.oidc_enforce = True
    enforced = create_app(settings)
    r = TestClient(enforced).post("/api/v1/auth/login", json={"username": "nouveau", "password": TEMP})
    assert r.status_code == 403 and "SSO" in r.json()["detail"] and "keryx_session" not in r.cookies
    # Une session intermédiaire déjà ouverte ne permet pas non plus d'enrôler ni d'obtenir une session complète
    c = TestClient(enforced)
    c.cookies.set("keryx_session", pending.cookies.get("keryx_session"))
    r = c.post("/api/v1/auth/enroll/start", json={"activation_code": code})
    assert r.status_code == 403 and "SSO" in r.json()["detail"]
    assert c.post("/api/v1/auth/enroll/finish", json={"code": "123456", "new_password": "un-autre-mot-de-passe"}).status_code == 401
    db.rollback()
    assert db.scalars(select(User).where(User.username == "nouveau")).one().enrolled is False
    assert any(e.details.get("etape") == "enrolement" for e in actions(db, "auth.local_login_refused"))
    # L'Admin garde son accès local de secours
    assert TestClient(enforced).post("/api/v1/auth/login", json={"username": "admin", "password": PASSWORD}).json()["next"] == "totp"


# ---------------------------------------------------------------- M6 : limiteur partagé (base) sur SQLite
def test_limiteur_en_base_ne_se_bloque_pas_lui_meme(settings, app, db, world, alert):
    code = create_unenrolled(app, db, world)
    settings.rate_limit_backend = "db"
    settings.login_user_limit = 4
    shared = create_app(settings)
    # Second facteur (la session de la requête a déjà lu en base quand le limiteur est appelé) : pas d'attente, pas de 500
    a = login(shared, db, "analyst_acme")
    assert a.get("/api/v1/me").json()["username"] == "analyst_acme"
    # Clé de sécurité, enrôlement, ingestion : mêmes appels au limiteur après une lecture
    c = TestClient(shared)
    assert c.post("/api/v1/auth/login", json={"username": "manager", "password": PASSWORD}).status_code == 200
    assert c.post("/api/v1/auth/webauthn/begin").status_code == 409        # aucune clé enregistrée
    e = TestClient(shared)
    assert e.post("/api/v1/auth/login", json={"username": "nouveau", "password": TEMP}).json()["next"] == "enroll"
    assert e.post("/api/v1/auth/enroll/start", json={"activation_code": code}).status_code == 200
    assert ingest(shared, "cle-inconnue", alert(ALERT_SSH_BRUTEFORCE)).status_code == 401
    assert ingest(shared, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).status_code == 201
    db.rollback()
    assert db.scalars(select(RateHit)).all()                                # les passages sont bien comptés en base
    # La limite s'applique toujours (4 tentatives par identifiant ; deux déjà comptées pour « manager »)
    codes = [TestClient(shared).post("/api/v1/auth/login", json={"username": "manager", "password": "faux"}).status_code
             for _ in range(4)]
    assert codes == [401, 401, 429, 429]
