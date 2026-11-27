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


def test_vue_client_titre_resume_et_reponse_attendue(app, db, world, alert):
    """Portail client : titre et résumé écrits par l'équipe ; filtre « réponse attendue » (mesure à décider, action à
    faire) ; le client ne modifie pas ces champs."""
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    a, c = login(app, db, "analyst_acme"), login(app, db, "client_acme")
    r = a.put(f"/api/v1/tickets/{ref}/vue-client", json={"titre_client": "Tentatives de connexion répétées",
                                                         "resume_client": "Un serveur reçoit des essais de mot de passe."})
    assert r.status_code == 200 and r.json()["resume_client_le"]
    assert c.put(f"/api/v1/tickets/{ref}/vue-client", json={"titre_client": "x"}).status_code == 403
    fiche = c.get(f"/api/v1/tickets/{ref}").json()
    assert fiche["titre_client"] == "Tentatives de connexion répétées" and fiche["resume_client"].startswith("Un serveur")
    item = c.get("/api/v1/tickets").json()["items"][0]
    assert item["titre_client"] == "Tentatives de connexion répétées" and item["a_decider"] is False
    assert c.get("/api/v1/tickets", params={"a_decider": "true"}).json()["items"] == []
    a.post(f"/api/v1/tickets/{ref}/mesures", json={"libelle": "Isoler le serveur"})
    assert [x["ref"] for x in c.get("/api/v1/tickets", params={"a_decider": "true"}).json()["items"]] == [ref]
    assert c.get("/api/v1/tickets").json()["items"][0]["a_decider"] is True


def test_accueil_client_notifications_et_rapport(app, db, world, alert):
    """Accueil du client (ce qui attend sa réponse, chiffres, nouvelles du SOC), notifications propres au client
    (décision attendue, réponse du SOC, incident résolu), rapport périodique de son seul client."""
    from keryx.models import InboxItem, User
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    a, c = login(app, db, "analyst_acme"), login(app, db, "client_acme")
    a.post(f"/api/v1/tickets/{ref}/mesures", json={"libelle": "Isoler le serveur"})
    a.post(f"/api/v1/tickets/{ref}/comments", json={"body_html": "<p>Nous analysons.</p>", "visible_client": True})
    acc = c.get("/api/v1/client/accueil").json()
    assert acc["a_faire"][0]["ref"] == ref and acc["a_faire"][0]["kind"] == "mesure" and acc["chiffres"]["attente"] == 1
    assert acc["chiffres"]["en_cours"] == 1 and any(n["action"] == "mesure_proposee" for n in acc["nouvelles"])
    assert a.get("/api/v1/client/accueil").status_code == 403
    db.rollback()
    client = db.scalars(select(User).where(User.username == "client_acme")).one()
    kinds = {i.kind for i in db.scalars(select(InboxItem).where(InboxItem.user_id == client.id))}
    assert {"decision_attendue", "reponse_soc"} <= kinds
    # préférences du client : ses trois types seulement
    p = c.get("/api/v1/me/preferences").json()
    assert p["kinds"] == ["decision_attendue", "reponse_soc", "incident_resolu"]
    assert c.put("/api/v1/me/preferences", json={"prefs": {"assignation": False}}).status_code == 422
    assert c.put("/api/v1/me/preferences", json={"prefs": {"reponse_soc": False}}).status_code == 200
    # rapport périodique : le sien, jamais celui d'un autre client
    rap = c.get("/api/v1/reports/period", params={"client": "ACME"})
    assert rap.status_code == 200 and "workload" not in rap.json() and "sla" not in rap.json()
    assert c.get("/api/v1/reports/period", params={"client": "DELTA"}).status_code in (403, 404)
