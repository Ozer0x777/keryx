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
