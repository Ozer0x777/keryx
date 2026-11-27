"""Indicateurs minimaux de PDIS IV.5.1.e, f, g produits par Keryx : durées min, moyenne, max de résolution ; délai
entre détection et notification ; séries mensuelles (créés, clos, avérés, alertes, ouverts cumulés par criticité) ;
20 règles les plus déclenchées ; comptes et authentifications du portail. Absents du rapport remis au client."""
from datetime import timedelta

from sqlalchemy import select

from keryx import notify
from keryx.models import Ticket

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login
from .test_notifications import FakeSMTP


def test_indicateurs(app, db, world, alert, settings, monkeypatch):
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host = "smtp.example.eu"
    login(app, db, "admin").patch("/api/v1/admin/clients/ACME", json={"contact_emails": ["soc@acme.example"]})
    login(app, db, "client_acme")                                    # une connexion réussie d'un compte Client
    r1 = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    encore = alert(ALERT_CRITICAL)
    encore["id"] = "1732111080.10"                                   # même règle, autre alerte : 2 alertes, 1 ticket
    ingest(app, world["keys"]["ACME"], encore)
    r2 = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    for ref, heures in ((r1, 2), (r2, 6)):
        t = db.scalars(select(Ticket).where(Ticket.ref == ref)).one()
        t.created_at = t.created_at - timedelta(hours=10)             # clôture fictive restée dans la période
        t.status, t.closed_at = "cloture", t.created_at + timedelta(hours=heures)
        t.qualified_at, t.verdict = t.created_at + timedelta(hours=1), "vrai_positif_avere"
    db.commit()
    m = login(app, db, "manager")
    ind = m.get("/api/v1/dashboard", params={"client": "ACME"}).json()["indicateurs_pdis"]
    assert ind["resolution_h"] == {"min": 2.0, "moyenne": 4.0, "max": 6.0, "n": 2}
    assert ind["detection_notification_min"]["Critique"]["n"] == 1
    mois = ind["par_mois"][-1]
    assert mois["crees"] == 2 and mois["clos"] == 2 and mois["averes"] == 2 and mois["alertes"] == 3
    assert sum(mois["ouverts_cumules"].values()) == 0
    top = ind["regles_les_plus_declenchees"]
    assert top[0]["regle"] == ALERT_CRITICAL["rule"]["id"] and top[0]["alertes"] == 2
    assert ind["portail"]["comptes_actifs"] == 1
    assert ind["portail"]["authentifications_par_mois"][-1]["reussies"] >= 1
    assert "non classé" in ind["qualification_par_typologie_h"]
    # capacité du stockage et disponibilité de l'envoi des notifications (IV.2.1.cc, IV.2.3.k, IV.5.1.e)
    cap = ind["capacite"]
    assert cap["base_octets"] > 0 and cap["disque_pieces"]["total_octets"] > 0
    assert 0 <= cap["disque_pieces"]["remplissage_pourcent"] <= 100 and cap["stockage_objet"] is False
    assert ind["notifications_par_mois"][-1]["envoyees"] >= 1 and ind["notifications_par_mois"][-1]["reussite_pourcent"] == 100.0
    # pas dans le rapport remis au client
    assert "indicateurs_pdis" not in m.get("/api/v1/reports/period", params={"client": "ACME"}).json()
