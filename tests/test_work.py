"""Confort de travail (v0.5) : recherche, SLA, liens, fusion, modèles, notifications, filtres, affectation en masse."""
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


def test_revue3_correctifs(app, db, world, alert):
    two_tickets(app, world, alert)
    m = login(app, db, "manager")
    # Filtre par assigné inconnu : aucun résultat (et non « tous les non-assignés »)
    assert m.get("/api/v1/tickets", params={"assignee": "personne-inconnue"}).json()["items"] == []
    # Fusion : le motif interne ne fuit pas vers le client
    m.post("/api/v1/tickets/ACME-2/merge", json={"into": "ACME-1", "reason": "SECRET-INTERNE"})
    cl = login(app, db, "client_acme").get("/api/v1/tickets/ACME-2")
    assert cl.status_code == 200 and "SECRET-INTERNE" not in cl.text
    assert "SECRET-INTERNE" in m.get("/api/v1/tickets/ACME-2").text
    # Audit : client inconnu -> rien
    assert login(app, db, "admin").get("/api/v1/audit/entries", params={"client": "NOPE"}).json()["items"] == []
    # Le badge relève aussi les échéances
    a = login(app, db, "analyst_acme")
    assert a.get("/api/v1/notifications/count").status_code == 200


def test_file_de_triage_tri_et_filtres_par_gravite(app, db, world, alert):
    """Non-régression : la file se trie par criticité et par gravité dans l'ordre métier (Critique > Élevée > Moyenne >
    Faible, pas l'ordre alphabétique), se filtre par gravité effective (gravité qualifiée, sinon criticité initiale) et
    par plusieurs statuts à la fois (« à qualifier » = nouveau + en évaluation)."""
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))   # ACME-1, niveau 10 : Moyenne
    ingest(app, world["keys"]["ACME"], alert(ALERT_NO_MITRE))         # ACME-2, niveau 8 : Faible
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))         # ACME-3, niveau 15 : Critique
    a = login(app, db, "analyst_acme")
    refs = lambda **p: [t["ref"] for t in a.get("/api/v1/tickets", params=p).json()["items"]]
    assert refs(sort="criticite", order="desc") == ["ACME-3", "ACME-1", "ACME-2"]
    assert refs(sort="criticite", order="asc") == ["ACME-2", "ACME-1", "ACME-3"]
    # Gravité : rien n'est qualifié, puis ACME-2 (criticité Faible) est qualifié Critique.
    assert a.post("/api/v1/tickets/ACME-2/status", json={"status": "en_evaluation"}).status_code == 200
    q = a.post("/api/v1/tickets/ACME-2/qualification",
               json={"verdict": "vrai_positif_avere", "dommages": "graves", "importance": "vital"})
    assert q.status_code == 200 and q.json()["gravite"] == "Critique"
    assert refs(sort="gravite", order="desc")[0] == "ACME-2"           # les tickets sans gravité viennent après
    assert refs(sort="gravite", order="asc")[-1] == "ACME-2"
    # Filtre par gravité effective : la gravité qualifiée prime sur la criticité initiale.
    assert set(refs(severity="Critique")) == {"ACME-2", "ACME-3"}
    assert refs(severity="Faible") == [] and refs(severity="Moyenne") == ["ACME-1"]
    assert a.get("/api/v1/tickets", params={"severity": "Grave"}).status_code == 422
    # Plusieurs statuts ; un seul statut reste accepté comme avant.
    assert set(refs(status="nouveau,en_evaluation")) == {"ACME-1", "ACME-2", "ACME-3"}
    assert refs(status="en_evaluation") == ["ACME-2"] and refs(status="en_reponse,cloture") == []
    assert set(refs(status="nouveau,en_evaluation,en_reponse", severity="Critique")) == {"ACME-2", "ACME-3"}
    # Un filtre enregistré conserve le critère de gravité.
    f = a.post("/api/v1/me/filters", json={"name": "Critiques", "params": {"severity": "Critique", "sort": "gravite"}})
    assert f.status_code == 201 and f.json()["params"] == {"severity": "Critique", "sort": "gravite"}
    # Le cloisonnement ne change pas : l'analyste d'un autre client ne voit rien de tout cela.
    assert login(app, db, "analyst_delta").get("/api/v1/tickets", params={"severity": "Critique"}).json()["items"] == []


def test_compteurs_de_la_file_cloisonnes_et_sans_entree_d_audit(app, db, world, alert):
    """Cartes de synthèse de la file : des nombres calculés par le serveur sur tous les tickets visibles, cloisonnés par
    client [PDIS IV.3.8.g]. Le relevé périodique ne lit plus la liste une seconde fois : aucune entrée d'audit ajoutée."""
    from keryx.models import AuditEntry
    two_tickets(app, world, alert)                                       # ACME-1 (Moyenne), ACME-2 (Faible)
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))            # ACME-3 (Critique)
    ingest(app, world["keys"]["DELTA"], alert(ALERT_CRITICAL))           # DELTA-1 (Critique)
    m = login(app, db, "manager")
    a = login(app, db, "analyst_acme")
    before = db.scalar(select(AuditEntry.seq).order_by(AuditEntry.seq.desc()).limit(1))
    db.rollback()
    c = m.get("/api/v1/tickets/counts").json()
    assert c["total"] == 4 and c["by_status"]["nouveau"] == 4 and c["by_status"]["cloture"] == 0
    assert c["open_by_severity"] == {"Faible": 1, "Moyenne": 1, "Élevée": 0, "Critique": 2}
    assert c["overdue"] == 0 and c["rex_en_attente"] == 0
    assert m.get("/api/v1/tickets/counts", params={"client": "delta"}).json()["total"] == 1
    mine = a.get("/api/v1/tickets/counts").json()
    assert mine["total"] == 3 and mine["open_by_severity"]["Critique"] == 1          # jamais les tickets d'un autre client
    assert a.get("/api/v1/tickets/counts", params={"client": "DELTA"}).json()["total"] == 0
    assert db.scalar(select(AuditEntry.seq).order_by(AuditEntry.seq.desc()).limit(1)) == before   # aucun ajout au journal
    db.rollback()
    # Les compteurs suivent la vie des tickets : qualification (gravité), échéance dépassée, clôture avec REX obligatoire
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "vrai_positif_avere", "dommages": "graves"})   # sensible × graves = Critique
    t = db.scalars(select(Ticket).where(Ticket.ref == "ACME-2")).one()
    t.created_at = utcnow() - timedelta(days=30)
    db.commit()
    c = a.get("/api/v1/tickets/counts").json()
    assert c["by_status"]["en_evaluation"] == 1 and c["open_by_severity"]["Critique"] == 2 and c["open_by_severity"]["Moyenne"] == 0
    assert c["overdue"] == 1
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_reponse"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "cloture"}).status_code == 200
    c = a.get("/api/v1/tickets/counts").json()
    assert c["rex_en_attente"] == 1 and c["by_status"]["cloture"] == 1 and c["open_by_severity"]["Critique"] == 1
    # Mêmes nombres que les filtres de la liste que chaque carte applique
    listed = lambda **p: a.get("/api/v1/tickets", params=p).json()["total"]
    assert listed(status="nouveau,en_evaluation") == c["by_status"]["nouveau"] + c["by_status"]["en_evaluation"]
    assert listed(status="nouveau,en_evaluation,en_reponse", severity="Critique") == c["open_by_severity"]["Critique"]
    assert listed(overdue=True) == c["overdue"] and listed(rex_en_attente=True) == c["rex_en_attente"]
    # Ni l'Admin (aucun accès aux tickets), ni le client (pas d'indicateurs internes)
    assert login(app, db, "admin").get("/api/v1/tickets/counts").status_code == 403
    assert login(app, db, "client_acme").get("/api/v1/tickets/counts").status_code == 403
    assert a.get("/api/v1/tickets/counts", params={"client": "x" * 40}).status_code == 422
