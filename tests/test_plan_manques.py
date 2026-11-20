"""Éléments du plan ajoutés après audit : historique du corps, propositions MITRE, validation ATT&CK,
limite de pièce par client, suggestion de gravité."""
import json

from sqlalchemy import select

from keryx.models import Tenant

from .conftest import ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login
from .test_attachments import REGISTRY, zip_bytes
from .test_ops import attack, bundle


def test_historique_des_versions_du_corps(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    original = a.get("/api/v1/tickets/ACME-1").json()["body_html"]
    a.put("/api/v1/tickets/ACME-1/body", json={"body_html": "<p>v2 de l'analyste</p>"})
    login(app, db, "manager").put("/api/v1/tickets/ACME-1/body", json={"body_html": "<p>v3 du manager</p>"})
    h = a.get("/api/v1/tickets/ACME-1/body-history").json()
    assert h["current"] == "<p>v3 du manager</p>"
    assert [v["actor"] for v in h["versions"]] == ["analyst_acme", "manager"]
    assert h["versions"][0]["html"] == original and h["versions"][1]["html"] == "<p>v2 de l'analyste</p>"
    assert all(v["ts"] and v["sha256"] and not v["truncated"] for v in h["versions"])
    assert login(app, db, "client_acme").get("/api/v1/tickets/ACME-1/body-history").status_code == 403  # interne
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    assert a.get("/api/v1/tickets/DELTA-1/body-history").status_code == 404                              # cloisonné


def test_propositions_de_table_mitre_pour_les_corrections_repetees(app, db, world, alert):
    a = login(app, db, "analyst_acme")
    for i in range(3):
        payload = alert(ALERT_NO_MITRE)
        payload["id"] = f"m{i}"
        payload["agent"]["id"] = f"00{i}"                                  # 3 agents : 3 tickets pour la même règle
        ingest(app, world["keys"]["ACME"], payload)
        a.post(f"/api/v1/tickets/ACME-{i + 1}/mitre", json={"techniques": ["T1110"]})
    m = login(app, db, "manager")
    sug = m.get("/api/v1/mitre/suggestions").json()["items"]
    assert sug == [{"rule_id": "100200", "rule_description": "Custom: repeated authentication failures",
                    "technique": "T1110", "count": 3, "name": "", "tactics": []}]
    assert m.get("/api/v1/mitre/suggestions", params={"min_count": 4}).json()["items"] == []
    # Acceptée : elle entre dans la table et n'est plus proposée
    assert m.post("/api/v1/mitre/mappings", json={"technique": "T1110", "rule_id": "100200"}).status_code == 201
    assert m.get("/api/v1/mitre/suggestions").json()["items"] == []
    assert login(app, db, "analyst_acme").get("/api/v1/mitre/suggestions").status_code == 403


def test_identifiants_mitre_valides_contre_le_referentiel_importe(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/tickets/ACME-1/mitre", json={"techniques": ["T9999"]}).status_code == 200   # pas de référentiel : format seul
    m = login(app, db, "manager")
    m.post("/api/v1/mitre/import", files={"file": ("a.json", json.dumps(bundle(attack("T1110", "Brute Force", ["credential-access"]))).encode(), "x")})
    r = a.post("/api/v1/tickets/ACME-1/mitre", json={"techniques": ["T1110", "T9998"]})
    assert r.status_code == 422 and "T9998" in r.json()["detail"]
    assert a.post("/api/v1/tickets/ACME-1/mitre", json={"techniques": ["T1110"]}).status_code == 200


def test_limite_de_piece_par_client(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    adm = login(app, db, "admin")
    assert adm.patch("/api/v1/admin/clients/ACME", json={"max_attachment_mb": 30}).status_code == 422   # plafond du plan : 20
    assert adm.patch("/api/v1/admin/clients/ACME", json={"max_attachment_mb": 1}).status_code == 200
    a = login(app, db, "analyst_acme")
    big = zip_bytes(content=b"x" * 2_000_000)                                                          # ~2 Mo non compressibles
    import os
    big = zip_bytes(content=os.urandom(2_000_000))
    r = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("g.zip", big, "application/zip")})
    assert r.status_code == 413 and "1 Mo" in r.json()["detail"]
    small = a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("p.zip", zip_bytes(), "application/zip")})
    assert small.status_code == 201
    assert adm.patch("/api/v1/admin/clients/ACME", json={"max_attachment_mb": None}).json()["max_attachment_mb"] is None
    assert a.post("/api/v1/tickets/ACME-1/attachments", data=REGISTRY, files={"file": ("g.zip", big, "application/zip")}).status_code == 201


def test_suggestion_de_gravite_selon_la_grille_du_client(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))     # agent « sensible »
    a = login(app, db, "analyst_acme")
    assert a.get("/api/v1/tickets/ACME-1").json()["severity_hint"] == {"limites": "Moyenne", "significatifs": "Élevée", "graves": "Critique"}
    grid = {"limites": {"standard": "Faible", "sensible": "Faible", "vital": "Faible"},
            "significatifs": {"standard": "Faible", "sensible": "Moyenne", "vital": "Moyenne"},
            "graves": {"standard": "Moyenne", "sensible": "Moyenne", "vital": "Moyenne"}}
    login(app, db, "admin").patch("/api/v1/admin/clients/ACME", json={"severity_grid": grid})
    assert a.get("/api/v1/tickets/ACME-1").json()["severity_hint"]["graves"] == "Moyenne"
    assert login(app, db, "client_acme").get("/api/v1/tickets/ACME-1").json()["severity_hint"] is None
