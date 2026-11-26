"""Fiche d'un ticket : commentaires et historique les plus récents, les plus anciens par paquets (curseur stable),
rapport complet, et cloisonnement du client conservé dans chaque paquet."""
from datetime import timedelta

from sqlalchemy import select

from keryx.ids import utcnow
from keryx.models import Comment, Ticket, TicketEvent, User

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login


def _remplir(db, ref, n_comments=120, n_events=250):
    t = db.scalars(select(Ticket).where(Ticket.ref == ref)).one()
    auteur = db.scalars(select(User).where(User.username == "analyst_acme")).one()
    base = utcnow() - timedelta(days=3)
    for i in range(n_comments):
        db.add(Comment(ticket_id=t.id, author_id=auteur.id, body_html=f"<p>commentaire {i:03d}</p>",
                       visible_client=(i % 3 == 0), created_at=base + timedelta(minutes=i)))
    for i in range(n_events):
        db.add(TicketEvent(ticket_id=t.id, actor="wazuh", action="occurrence", details={"n": i},
                           visible_client=(i % 5 == 0), ts=base + timedelta(minutes=i)))
    db.commit()


def test_fiche_recente_puis_plus_anciens(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    _remplir(db, ref)
    a = login(app, db, "analyst_acme")
    t = a.get(f"/api/v1/tickets/{ref}").json()
    assert len(t["comments"]) == 50 and t["comments"][-1]["body_html"] == "<p>commentaire 119</p>"
    assert t["comments_older"] == 70 and len(t["events"]) == 100 and t["events_older"] >= 150
    vus, older, avant = [c["body_html"] for c in t["comments"]], t["comments_older"], t["comments"][0]["id"]
    while older:
        r = a.get(f"/api/v1/tickets/{ref}/comments", params={"before": avant}).json()
        vus = [c["body_html"] for c in r["items"]] + vus
        older, avant = r["older"], r["items"][0]["id"]
    assert vus == [f"<p>commentaire {i:03d}</p>" for i in range(120)]      # tout, dans l'ordre, sans doublon
    complet = a.get(f"/api/v1/tickets/{ref}", params={"complet": True}).json()
    assert len(complet["comments"]) == 120 and complet["comments_older"] == 0 and complet["events_older"] == 0


def test_client_ne_recoit_que_ce_qui_lui_est_destine(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    _remplir(db, ref)
    a, c = login(app, db, "analyst_acme"), login(app, db, "client_acme")
    t = c.get(f"/api/v1/tickets/{ref}").json()
    assert len(t["comments"]) == 40 and t["comments_older"] == 0                # 120 // 3 visibles, tous sur la page
    interne = next(x["id"] for x in a.get(f"/api/v1/tickets/{ref}").json()["comments"] if not x["visible_client"])
    assert c.get(f"/api/v1/tickets/{ref}/comments", params={"before": interne}).status_code == 404   # curseur interne : inconnu
    ev = c.get(f"/api/v1/tickets/{ref}").json()
    r = c.get(f"/api/v1/tickets/{ref}/events", params={"before": ev["events"][0]["id"]}).json()
    assert all(x["action"] == "occurrence" for x in r["items"])
    assert c.get(f"/api/v1/tickets/{ref}/events", params={"before": "x" * 65}).status_code == 422
    # Un autre client ne lit rien, même avec un identifiant valide
    d = login(app, db, "client_delta") if "client_delta" in world["users"] else None
    if d is not None:
        assert d.get(f"/api/v1/tickets/{ref}/comments", params={"before": interne}).status_code in (403, 404)
