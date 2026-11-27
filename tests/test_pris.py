"""Réponse aux incidents (PRIS v3.2) : compréhension structurée (VI.5.3.e), posture et discrétion (VI.3.b) avec refus
des recherches en source ouverte en discrétion élevée (VI.5.2.4), cadre du rapport (VI.7), mesures d'endiguement
décidées par le commanditaire (VI.5.4), registre de crise complété (VI.5.5.1), point de situation (VI.6.a)."""
from sqlalchemy import select

from keryx.models import TicketEvent

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login


def _ticket(app, world, alert):
    return ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]


def test_comprehension_posture_rapport(app, db, world, alert):
    ref = _ticket(app, world, alert)
    a = login(app, db, "analyst_acme")
    r = a.put(f"/api/v1/tickets/{ref}/pris/comprehension", json={
        "attaquant_present": "oui", "mo_compromission_initiale": "Hameçonnage", "niveau_menace": "systemique",
        "comptes_compromis": "admin.local"})
    assert r.status_code == 200 and r.json()["pris"]["comprehension"]["niveau_menace"] == "systemique"
    assert a.put(f"/api/v1/tickets/{ref}/pris/comprehension", json={"niveau_menace": "terrible"}).status_code == 422
    assert a.put(f"/api/v1/tickets/{ref}/pris/comprehension", json={"inconnu": "x"}).status_code == 422
    assert a.put(f"/api/v1/tickets/{ref}/pris/autre", json={}).status_code == 404
    # vider un champ le retire
    r = a.put(f"/api/v1/tickets/{ref}/pris/comprehension", json={"comptes_compromis": ""})
    assert "comptes_compromis" not in r.json()["pris"]["comprehension"]
    r = a.put(f"/api/v1/tickets/{ref}/pris/rapport", json={
        "qualifiee": True, "niveau": "substantiel", "activites": ["PCI", "REC", "INV"], "analyse": ["systeme"],
        "equipe": [{"nom": "Analyste A", "role": "pilote_investigation", "activites": "PCI"}],
        "synthese_manageriale": "Un compte a été usurpé…", "interlocuteurs": [{"nom": "RSSI", "fonction": "RSSI", "entite": "ACME"}]})
    assert r.status_code == 200 and r.json()["pris"]["rapport"]["activites"] == ["REC", "INV", "PCI"]
    assert a.put(f"/api/v1/tickets/{ref}/pris/rapport", json={"equipe": [{"nom": "X", "role": "stagiaire"}]}).status_code == 422
    fiche = a.get(f"/api/v1/tickets/{ref}").json()
    assert fiche["pris"]["comprehension"]["attaquant_present"] == "oui"
    assert "pris" not in login(app, db, "client_acme").get(f"/api/v1/tickets/{ref}").json()
    assert login(app, db, "client_acme").put(f"/api/v1/tickets/{ref}/pris/comprehension", json={}).status_code == 403
    db.rollback()
    assert db.scalars(select(TicketEvent).where(TicketEvent.action == "pris_comprehension")).first()


def test_discretion_elevee_bloque_les_sources_ouvertes(app, db, world, alert):
    from sqlalchemy import update

    from keryx.models import Tenant
    ref = _ticket(app, world, alert)
    db.execute(update(Tenant).values(virustotal_autorise=True))
    db.commit()
    a = login(app, db, "analyst_acme")
    r = a.put(f"/api/v1/tickets/{ref}/pris/posture", json={"discretion": "eleve", "demarche": "Copie à froid"})
    assert r.status_code == 200
    db.rollback()
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "pris_posture")).one()
    assert ev.details["discretion"] == "eleve"
    from fastapi.testclient import TestClient  # noqa: F401 - VirusTotal non configuré ici : le refus vient avant
    app.state.settings.virustotal_enabled = True
    r = a.post(f"/api/v1/tickets/{ref}/virustotal", json={"source": "saisie", "hash": "a" * 64})
    assert r.status_code == 409 and "discrétion" in r.json()["detail"]


def test_mesures_d_endiguement_decidees_par_le_commanditaire(app, db, world, alert):
    ref = _ticket(app, world, alert)
    a, c = login(app, db, "analyst_acme"), login(app, db, "client_acme")
    assert c.post(f"/api/v1/tickets/{ref}/mesures", json={"libelle": "Isoler le poste"}).status_code == 403
    r = a.post(f"/api/v1/tickets/{ref}/mesures", json={"type": "urgence", "libelle": "Couper l'accès Internet du site"})
    assert r.status_code == 201
    m = r.json()["mesures"][0]
    assert m["etat"] == "proposee" and m["type"] == "urgence"
    assert c.get(f"/api/v1/tickets/{ref}").json()["mesures"][0]["libelle"].startswith("Couper")
    assert c.patch(f"/api/v1/tickets/{ref}/mesures/{m['id']}", json={"etat": "appliquee"}).status_code == 403
    r = c.patch(f"/api/v1/tickets/{ref}/mesures/{m['id']}", json={"etat": "acceptee", "commentaire": "Validé par la DSI"})
    assert r.status_code == 200 and r.json()["mesures"][0]["decision_par"]
    assert a.patch(f"/api/v1/tickets/{ref}/mesures/{m['id']}", json={"etat": "appliquee"}).json()["mesures"][0]["etat"] == "appliquee"
    assert a.patch(f"/api/v1/tickets/{ref}/mesures/{m['id']}", json={"etat": "acceptee"}).status_code == 409  # déjà appliquée
    assert c.patch(f"/api/v1/tickets/{ref}/mesures/{m['id']}", json={"etat": "refusee"}).status_code == 409  # pas de retour
    # décision rapportée par l'équipe (téléphone, réunion) : son auteur est exigé
    m2 = a.post(f"/api/v1/tickets/{ref}/mesures", json={"libelle": "Désactiver le compte usurpé"}).json()["mesures"][-1]
    assert a.patch(f"/api/v1/tickets/{ref}/mesures/{m2['id']}", json={"etat": "appliquee"}).status_code == 409  # non décidée
    assert a.patch(f"/api/v1/tickets/{ref}/mesures/{m2['id']}", json={"etat": "refusee"}).status_code == 422   # qui a décidé ?
    r = a.patch(f"/api/v1/tickets/{ref}/mesures/{m2['id']}", json={"etat": "refusee", "decision_par": "M. le RSSI, par téléphone"})
    assert next(x for x in r.json()["mesures"] if x["id"] == m2["id"])["decision_par"].startswith("M. le RSSI")
    r = a.patch(f"/api/v1/tickets/{ref}/mesures/{m2['id']}", json={"etat": "proposee"})                        # réévaluation
    assert next(x for x in r.json()["mesures"] if x["id"] == m2["id"])["decision_par"] is None
    evs = [e["action"] for e in c.get(f"/api/v1/tickets/{ref}").json()["events"]]
    assert "mesure_proposee" in evs and "mesure_acceptee" in evs


def test_registre_de_crise_complete(app, db, world, alert):
    ref = _ticket(app, world, alert)
    m = login(app, db, "manager")
    assert m.post(f"/api/v1/tickets/{ref}/crisis", json={"active": True, "reason": "Rançongiciel sur le SI de production"}).status_code == 200
    ajout = lambda **k: m.post(f"/api/v1/tickets/{ref}/crisis/entries", json=k)     # noqa: E731
    obj = ajout(kind="objectif", body="Rétablir la messagerie").json()["items"][-1]
    dec = ajout(kind="decision", body="Couper les accès VPN", entite="Cellule de crise stratégique").json()["items"][-1]
    act = ajout(kind="action", body="Reconstruire le serveur de messagerie", owner="DSI", parent_id=obj["id"], decision_id=dec["id"]).json()["items"][-1]
    assert act["parent_id"] == obj["id"] and act["decision_id"] == dec["id"] and dec["entite"].startswith("Cellule")
    assert ajout(kind="action", body="x", parent_id=dec["id"]).status_code == 422          # parent : un objectif
    crit = ajout(kind="critere_sortie", body="Messagerie rétablie pour 95 % des utilisateurs").json()["items"][-1]
    dero = ajout(kind="derogation", body="Comptes administrateurs partagés", risque="Traçabilité réduite").json()["items"][-1]
    assert dero["risque"] == "Traçabilité réduite"
    r = m.patch(f"/api/v1/tickets/{ref}/crisis/entries/{obj['id']}", json={"valide_par": "Cellule de crise stratégique"})
    assert r.status_code == 200 and next(x for x in r.json()["items"] if x["id"] == obj["id"])["valide_le"]
    r = m.patch(f"/api/v1/tickets/{ref}/crisis/entries/{crit['id']}", json={"done": True})
    assert next(x for x in r.json()["items"] if x["id"] == crit["id"])["done"] is True
    assert m.patch(f"/api/v1/tickets/{ref}/crisis/entries/{dec['id']}", json={"done": True}).status_code == 422


def test_point_de_situation(app, db, world, alert):
    ref = _ticket(app, world, alert)
    a = login(app, db, "analyst_acme")
    a.put(f"/api/v1/tickets/{ref}/pris/comprehension", json={"attaquant_present": "inconnu"})
    a.post(f"/api/v1/tickets/{ref}/mesures", json={"libelle": "Réinitialiser les mots de passe"})
    p = a.get(f"/api/v1/tickets/{ref}/point-situation", params={"heures": 24}).json()
    assert p["comprehension"]["attaquant_present"] == "inconnu" and p["mesures"][0]["libelle"].startswith("Réinit")
    assert any(x["action"] == "mesure_proposee" for x in p["actions"])
    assert login(app, db, "client_acme").get(f"/api/v1/tickets/{ref}/point-situation").status_code == 403
