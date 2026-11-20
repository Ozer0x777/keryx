"""Régressions de la deuxième relecture : pièces sur ticket clos, REX vide, affectation, CSP, fusion."""
import copy

from sqlalchemy import select

from keryx.models import User

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login
from .test_attachments import REGISTRY, png_with_exif, zip_bytes


def _close_as_false_positive(a):
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif"}).status_code == 200


def test_piece_refusee_sur_ticket_clos(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    _close_as_false_positive(a)
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY,
               files={"file": ("p.zip", zip_bytes(), "application/octet-stream")})
    assert r.status_code == 409


def test_rex_html_vide_refuse(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification",
           json={"verdict": "vrai_positif_avere", "dommages": "significatifs", "impact": "x"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_reponse"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "cloture"})
    a.put("/api/v1/tickets/ACME-1/synthese", json={"rex_html": "<p><br></p>"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "retour_experience"}).status_code == 409


def test_affectation_compte_desactive_refusee(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    m = db.scalars(select(User).where(User.username == "manager")).one()
    m.active = False
    db.commit()
    r = a.post("/api/v1/tickets/ACME-1/assign", json={"username": "manager"})
    assert r.status_code == 422


def test_csp_stricte_sur_piece_en_ligne(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY,
               files={"file": ("i.png", png_with_exif(), "image/png")})
    assert r.status_code == 201, r.text
    dl = a.get(f"/api/v1/attachments/{r.json()['id']}/content")
    assert dl.headers["content-security-policy"] == "default-src 'none'; sandbox"


def test_fusion_ne_baisse_pas_la_criticite(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    hi = copy.deepcopy(ALERT_SSH_BRUTEFORCE)
    hi["id"] = "autre.1"
    hi["rule"]["level"] = 13
    assert ingest(app, world["keys"]["ACME"], hi).json()["status"] == "merged"
    a = login(app, db, "analyst_acme")
    assert a.get("/api/v1/tickets/ACME-1").json()["criticite_initiale"] == "Élevée"
