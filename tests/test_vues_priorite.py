"""Vues de priorisation de la file (ADR-0025) : critiques non assignés, en attente du client, dossiers incomplets."""
from .conftest import ALERT_CRITICAL, ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login

ACME_KEY = "ACME"


def trois_tickets(app, world, alert):
    ingest(app, world["keys"][ACME_KEY], alert(ALERT_SSH_BRUTEFORCE))   # ACME-1 (Moyenne)
    ingest(app, world["keys"][ACME_KEY], alert(ALERT_NO_MITRE))         # ACME-2 (Faible)
    ingest(app, world["keys"][ACME_KEY], alert(ALERT_CRITICAL))         # ACME-3 (Critique)


def refs(c, **p):
    return sorted(t["ref"] for t in c.get("/api/v1/tickets", params=p).json()["items"])


def comment(c, ref, visible):
    return c.post(f"/api/v1/tickets/{ref}/comments", json={"body_html": "<p>message</p>", "visible_client": visible})


def test_critiques_non_assignes(app, db, world, alert):
    trois_tickets(app, world, alert)
    a = login(app, db, "analyst_acme")
    assert a.get("/api/v1/tickets/counts").json()["critical_unassigned"] == 1
    assert refs(a, status="nouveau,en_evaluation,en_reponse", severity="Critique", assignee="none") == ["ACME-3"]
    assert a.post("/api/v1/tickets/ACME-3/assign", json={"username": "analyst_acme"}).status_code == 200
    assert a.get("/api/v1/tickets/counts").json()["critical_unassigned"] == 0
    assert refs(a, status="nouveau,en_evaluation,en_reponse", severity="Critique", assignee="none") == []


def test_en_attente_du_client(app, db, world, alert):
    trois_tickets(app, world, alert)
    a, c = login(app, db, "analyst_acme"), login(app, db, "client_acme")
    n = lambda: a.get("/api/v1/tickets/counts").json()["awaiting_client"]  # noqa: E731
    assert n() == 0 and refs(a, awaiting_client="true") == []
    assert comment(a, "ACME-1", False).status_code == 201          # interne : le client ne l'a pas vu
    assert n() == 0
    assert comment(a, "ACME-1", True).status_code == 201           # question visible du client : on attend sa réponse
    assert n() == 1 and refs(a, awaiting_client="true") == ["ACME-1"]
    assert comment(c, "ACME-1", True).status_code == 201           # le client répond : plus en attente
    assert n() == 0
    assert comment(a, "ACME-1", True).status_code == 201           # nouvelle relance
    assert refs(a, awaiting_client="true") == ["ACME-1"]
    assert comment(a, "ACME-1", False).status_code == 201          # une note interne ne change rien
    assert n() == 1


def test_en_attente_du_client_ticket_clos_exclu(app, db, world, alert):
    trois_tickets(app, world, alert)
    a = login(app, db, "analyst_acme")
    comment(a, "ACME-1", True)
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque confirmée."})
    assert refs(a, awaiting_client="true") == []


def test_dossiers_incomplets(app, db, world, alert):
    trois_tickets(app, world, alert)
    a = login(app, db, "analyst_acme")
    assert a.get("/api/v1/tickets/counts").json()["incomplete"] == 0   # nouveau : dossier en cours de constitution
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "vrai_positif_avere", "dommages": "limites"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_reponse"}).status_code == 200
    assert refs(a, incomplete="true") == ["ACME-1"]                    # ni assigné ni synthèse
    a.post("/api/v1/tickets/ACME-1/assign", json={"username": "analyst_acme"})
    assert refs(a, incomplete="true") == ["ACME-1"]                    # synthèse encore vide
    a.put("/api/v1/tickets/ACME-1/synthese", json={"chronologie": "<p>c</p>", "mode_operatoire": "<p>m</p>"})
    assert refs(a, incomplete="true") == ["ACME-1"]                    # il manque le périmètre
    a.put("/api/v1/tickets/ACME-1/synthese", json={"chronologie": "<p>c</p>", "mode_operatoire": "<p>m</p>", "perimetre": "<p>p</p>"})
    assert refs(a, incomplete="true") == []
    assert a.get("/api/v1/tickets/counts").json()["incomplete"] == 0


def test_vues_reservees_a_l_equipe(app, db, world, alert):
    trois_tickets(app, world, alert)
    c = login(app, db, "client_acme")
    assert c.get("/api/v1/tickets", params={"awaiting_client": "true"}).status_code == 403
    assert c.get("/api/v1/tickets", params={"incomplete": "true"}).status_code == 403
    assert c.get("/api/v1/tickets").status_code == 200
