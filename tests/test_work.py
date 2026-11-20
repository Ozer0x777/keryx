"""Confort de travail (v0.5) : recherche, SLA, liens, fusion, modèles, notifications, filtres, affectation en masse."""
import copy
from datetime import timedelta

from sqlalchemy import select

from keryx.ids import utcnow
from keryx.models import Tenant, Ticket

from .conftest import ALERT_CRITICAL, ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login


def two_tickets(app, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))   # ACME-1
    ingest(app, world["keys"]["ACME"], alert(ALERT_NO_MITRE))         # ACME-2


def test_recherche_tri_et_filtres(app, db, world, alert):
    two_tickets(app, world, alert)
    a = login(app, db, "analyst_acme")
    refs = lambda **p: [t["ref"] for t in a.get("/api/v1/tickets", params=p).json()["items"]]
    assert refs(q="brute force") == ["ACME-1"]
    assert refs(q="pc-rh-03") == ["ACME-2"]
    assert refs(q="10.20.1.15") == ["ACME-1"]
    assert refs(q="%") == []                       # les jokers sont échappés
    assert refs(sort="ref", order="asc") == ["ACME-1", "ACME-2"]
    assert refs(sort="ref", order="desc") == ["ACME-2", "ACME-1"]
    assert a.get("/api/v1/tickets", params={"sort": "x"}).status_code == 422
    assert refs(assignee="none") == ["ACME-2", "ACME-1"] or set(refs(assignee="none")) == {"ACME-1", "ACME-2"}
    assert refs(assignee="me") == []
    a.post("/api/v1/tickets/ACME-1/assign", json={"username": "analyst_acme"})
    assert refs(assignee="me") == ["ACME-1"]


def test_recherche_dans_les_commentaires_jamais_les_internes_pour_le_client(app, db, world, alert):
    two_tickets(app, world, alert)
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>piste interne mimikatz</p>", "visible_client": False})
    a.post("/api/v1/tickets/ACME-2/comments", json={"body_html": "<p>point visible rotation</p>", "visible_client": True})
    assert [t["ref"] for t in a.get("/api/v1/tickets", params={"q": "mimikatz"}).json()["items"]] == ["ACME-1"]
    c = login(app, db, "client_acme")
    assert c.get("/api/v1/tickets", params={"q": "mimikatz"}).json()["items"] == []
    assert [t["ref"] for t in c.get("/api/v1/tickets", params={"q": "rotation"}).json()["items"]] == ["ACME-2"]


def test_sla_echeances_et_depassement(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    a = login(app, db, "analyst_acme")
    t = a.get("/api/v1/tickets/ACME-1").json()
    assert t["due_qualification"] and t["due_resolution"] and t["overdue"] is False
    assert login(app, db, "client_acme").get("/api/v1/tickets/ACME-1").json().get("due_resolution") is None  # interne
    row = db.scalars(select(Ticket)).one()
    row.created_at = utcnow() - timedelta(hours=3)     # Critique : qualification attendue sous 1 h
    db.commit()
    assert a.get("/api/v1/tickets/ACME-1").json()["overdue"] is True
    assert [x["ref"] for x in a.get("/api/v1/tickets", params={"overdue": "true"}).json()["items"]] == ["ACME-1"]
    # Un SLA propre au client prime sur la valeur par défaut
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    acme.sla = {"Critique": {"qualification": 24, "resolution": 48}}
    db.commit()
    assert a.get("/api/v1/tickets/ACME-1").json()["overdue"] is False


def test_liens_cloisonnes_et_fusion(app, db, world, alert):
    two_tickets(app, world, alert)
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))  # DELTA-1
    m = login(app, db, "manager")
    assert m.post("/api/v1/tickets/ACME-1/links", json={"ref": "DELTA-1", "kind": "lie"}).status_code == 422
    assert m.post("/api/v1/tickets/ACME-1/links", json={"ref": "ACME-1", "kind": "lie"}).status_code == 422
    assert m.post("/api/v1/tickets/ACME-1/links", json={"ref": "ACME-2", "kind": "inconnu"}).status_code == 422
    r = m.post("/api/v1/tickets/ACME-1/links", json={"ref": "ACME-2", "kind": "parent"})
    assert r.status_code == 201 and r.json()["items"][0]["ref"] == "ACME-2"
    assert m.get("/api/v1/tickets/ACME-2/links").json()["items"][0]["kind"] == "enfant"
    assert m.post("/api/v1/tickets/ACME-2/links", json={"ref": "ACME-1", "kind": "lie"}).status_code == 409
    # Un analyste d'ACME ne peut pas lier à un ticket d'un autre client (introuvable)
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/tickets/ACME-1/links", json={"ref": "DELTA-1", "kind": "lie"}).status_code == 404
    # Fusion
    link_id = m.get("/api/v1/tickets/ACME-1/links").json()["items"][0]["id"]
    assert m.delete(f"/api/v1/tickets/ACME-1/links/{link_id}").json()["items"] == []
    merged = m.post("/api/v1/tickets/ACME-2/merge", json={"into": "ACME-1", "reason": "même source"})
    assert merged.status_code == 200 and merged.json()["occurrences"] == 2
    assert m.get("/api/v1/tickets/ACME-2").json()["status"] == "faux_positif"
    assert m.get("/api/v1/tickets/ACME-1").json()["raw_alerts"] == 2
    assert m.post("/api/v1/tickets/ACME-2/merge", json={"into": "ACME-1", "reason": "encore"}).status_code == 409  # clos
    assert m.get("/api/v1/audit/verify").status_code == 403  # réservé à l'admin
    assert login(app, db, "admin").get("/api/v1/audit/verify").json()["chain_ok"] is True


def test_modeles(app, db, world):
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/templates", json={"kind": "commentaire", "name": "Accusé", "body_html": "<p>Pris en charge</p><script>x</script>"}).status_code == 403
    r = a.post("/api/v1/templates", json={"kind": "commentaire", "name": "Accusé", "body_html": "<p>Pris en charge</p><script>x</script>", "client": "ACME"})
    assert r.status_code == 201
    m = login(app, db, "manager")
    assert m.post("/api/v1/templates", json={"kind": "synthese", "name": "REX type", "body_html": "<p>Cause</p>"}).status_code == 201
    items = a.get("/api/v1/templates").json()["items"]
    assert {i["name"] for i in items} == {"Accusé", "REX type"} and all("<script" not in i["body_html"] for i in items)
    assert login(app, db, "analyst_delta").get("/api/v1/templates").json()["items"][0]["name"] == "REX type"  # pas celui d'ACME
    assert login(app, db, "client_acme").get("/api/v1/templates").status_code == 403
    assert a.delete(f"/api/v1/templates/{r.json()['id']}").status_code == 200


def test_notifications_assignation_mention_reponse_client(app, db, world, alert):
    two_tickets(app, world, alert)
    m = login(app, db, "manager")
    a = login(app, db, "analyst_acme")
    m.post("/api/v1/tickets/ACME-1/assign", json={"username": "analyst_acme"})
    notes = a.get("/api/v1/notifications").json()
    assert notes["unread"] == 1 and notes["items"][0]["kind"] == "assignation" and notes["items"][0]["ref"] == "ACME-1"
    assert "title" not in notes["items"][0]  # jamais de détail de l'incident
    m.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>cc @analyst_acme voir ceci</p>", "visible_client": False})
    assert a.get("/api/v1/notifications/count").json()["unread"] == 2
    # Mention d'un agent hors du client : rien
    m.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>cc @analyst_delta</p>", "visible_client": False})
    assert login(app, db, "analyst_delta").get("/api/v1/notifications").json()["unread"] == 0
    c = login(app, db, "client_acme")
    c.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>des nouvelles ?</p>", "visible_client": True})
    kinds = [n["kind"] for n in a.get("/api/v1/notifications").json()["items"]]
    assert "reponse_client" in kinds
    a.post("/api/v1/notifications/read")
    assert a.get("/api/v1/notifications/count").json()["unread"] == 0
    # Préférence : plus de notification de mention
    assert a.put("/api/v1/me/preferences", json={"prefs": {"mention": False}}).status_code == 200
    m.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>@analyst_acme encore</p>", "visible_client": False})
    assert a.get("/api/v1/notifications/count").json()["unread"] == 0
    assert a.put("/api/v1/me/preferences", json={"prefs": {"autre": True}}).status_code == 422


def test_notification_echeance_une_seule_fois(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/assign", json={"username": "analyst_acme"})
    row = db.scalars(select(Ticket)).one()
    row.created_at = utcnow() - timedelta(hours=3)
    db.commit()
    first = a.get("/api/v1/notifications").json()
    assert [n["kind"] for n in first["items"]] == ["echeance"]
    assert len(a.get("/api/v1/notifications").json()["items"]) == 1  # pas de doublon


def test_filtres_enregistres_et_affectation_en_masse(app, db, world, alert):
    two_tickets(app, world, alert)
    a = login(app, db, "analyst_acme")
    f = a.post("/api/v1/me/filters", json={"name": "Mes urgences", "params": {"assignee": "me", "overdue": True, "evil": "x"}})
    assert f.status_code == 201 and f.json()["params"] == {"assignee": "me", "overdue": True}
    assert login(app, db, "analyst_delta").get("/api/v1/me/filters").json()["items"] == []  # propres à chacun
    assert a.delete(f"/api/v1/me/filters/{f.json()['id']}").status_code == 200
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    m = login(app, db, "manager")
    r = m.post("/api/v1/tickets/bulk-assign", json={"refs": ["ACME-1", "ACME-2", "DELTA-1"], "username": "analyst_acme"}).json()
    assert r["done"] == 2 and [x["ok"] for x in r["results"]] == [True, True, False]  # DELTA-1 : pas son client
    assert len(a.get("/api/v1/tickets", params={"assignee": "me"}).json()["items"]) == 2
    assert m.post("/api/v1/tickets/bulk-assign", json={"refs": ["ACME-1"], "username": None}).json()["done"] == 1
