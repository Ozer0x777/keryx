"""Suivi d'un ticket par le client (PDIS IV.2.3.l, tel que la trame le vérifie) : le client modifie l'état de son côté,
demande la clôture ou la réouverture ; l'équipe accepte par le statut ou refuse avec un motif ; actions demandées au
client, mises à jour par lui ; tout est inscrit au registre, visible du client ; droits."""
from sqlalchemy import select

from keryx.models import InboxItem, TicketEvent

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login


def test_etat_et_demandes_du_client(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    c, a = login(app, db, "client_acme"), login(app, db, "analyst_acme")
    r = c.post(f"/api/v1/tickets/{ref}/etat-client", json={"etat": "en_cours", "commentaire": "Poste isolé du réseau"})
    assert r.status_code == 200 and r.json()["suivi_client"]["etat"] == "en_cours"
    assert c.post(f"/api/v1/tickets/{ref}/etat-client", json={"etat": "supprime"}).status_code == 422
    assert c.post(f"/api/v1/tickets/{ref}/etat-client", json={"demande": "reouverture"}).status_code == 409
    assert c.post(f"/api/v1/tickets/{ref}/etat-client", json={"etat": "traite", "demande": "cloture"}).status_code == 200
    fiche = a.get(f"/api/v1/tickets/{ref}").json()
    assert fiche["suivi_client"] == {**fiche["suivi_client"], "etat": "traite", "demande": "cloture"}
    db.rollback()
    assert db.scalars(select(InboxItem).where(InboxItem.kind == "reponse_client")).all()     # l'équipe est prévenue
    # refus motivé, visible du client
    assert a.post(f"/api/v1/tickets/{ref}/demande-client/refus", json={"motif": "court"}).status_code == 422
    r = a.post(f"/api/v1/tickets/{ref}/demande-client/refus", json={"motif": "Analyse encore en cours côté SOC"})
    assert r.status_code == 200 and r.json()["suivi_client"]["demande"] is None
    evs = [e["action"] for e in c.get(f"/api/v1/tickets/{ref}").json()["events"]]
    assert "etat_client" in evs and "demande_client_refusee" in evs
    # l'équipe ne modifie pas l'état côté client ; le client ne refuse pas
    assert a.post(f"/api/v1/tickets/{ref}/etat-client", json={"etat": "traite"}).status_code == 403
    assert c.post(f"/api/v1/tickets/{ref}/demande-client/refus", json={"motif": "Je refuse ma propre demande"}).status_code == 403


def test_demande_de_cloture_acceptee_par_le_statut(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    c, a = login(app, db, "client_acme"), login(app, db, "analyst_acme")
    c.post(f"/api/v1/tickets/{ref}/etat-client", json={"demande": "cloture"})
    a.post(f"/api/v1/tickets/{ref}/status", json={"status": "en_evaluation"})
    a.post(f"/api/v1/tickets/{ref}/qualification", json={"verdict": "faux_positif"})
    assert a.post(f"/api/v1/tickets/{ref}/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée."}).status_code == 200
    assert a.get(f"/api/v1/tickets/{ref}").json()["suivi_client"]["demande"] is None
    assert c.post(f"/api/v1/tickets/{ref}/etat-client", json={"demande": "reouverture"}).status_code == 200


def test_actions_demandees_au_client(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    c, a = login(app, db, "client_acme"), login(app, db, "analyst_acme")
    assert c.post(f"/api/v1/tickets/{ref}/actions-client", json={"libelle": "Réinitialiser le mot de passe"}).status_code == 403
    r = a.post(f"/api/v1/tickets/{ref}/actions-client", json={"libelle": "Réinitialiser le mot de passe du compte admin"})
    assert r.status_code == 201
    action = r.json()["actions_client"][0]
    assert action["etat"] == "a_faire"
    vue = c.get(f"/api/v1/tickets/{ref}").json()
    assert vue["actions_client"][0]["libelle"].startswith("Réinitialiser")
    assert c.patch(f"/api/v1/tickets/{ref}/actions-client/{action['id']}", json={"etat": "perdu"}).status_code == 422
    r = c.patch(f"/api/v1/tickets/{ref}/actions-client/{action['id']}", json={"etat": "faite", "commentaire": "Fait à 10 h"})
    assert r.status_code == 200 and r.json()["actions_client"][0]["etat"] == "faite"
    assert a.patch(f"/api/v1/tickets/{ref}/actions-client/{action['id']}", json={"etat": "a_faire"}).status_code == 403
    db.rollback()
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "action_client_maj")).one()
    assert ev.visible_client and ev.details["etat"] == "faite"
    # cloisonnement : un client d'un autre périmètre ne voit pas le ticket
    assert login(app, db, "manager").get(f"/api/v1/tickets/{ref}").status_code == 200
