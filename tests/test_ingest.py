"""Ingestion Wazuh. [PDIS IV.2.1.w, aa, bb ; IV.2.3.g, h]"""
from sqlalchemy import select

from keryx.ids import as_utc
from keryx.models import Notification, RawAlert, Ticket

from .conftest import (
    ALERT_CRITICAL, ALERT_LOW, ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ALERT_XSS, ingest,
)


def test_ticket_cree_et_pre_rempli(app, db, world, alert):
    r = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    assert r.status_code == 201
    assert r.json()["ticket"] == "ACME-1"
    t = db.scalars(select(Ticket).where(Ticket.ref == "ACME-1")).one()
    # Contenu minimal PDIS IV.2.1.w
    assert t.title.startswith("sshd: brute force") and "srv-web-01" in t.title
    assert t.rule_id == "5712" and t.rule_level == 10 and "sshd" in t.rule_groups
    assert t.agent_id == "003" and t.agent_ip == "10.20.1.15"
    assert t.criticite_initiale == "Moyenne"          # niveau 10 → Moyenne
    assert t.importance == "sensible"                 # label d'agent
    assert t.mitre[0]["id"] == "T1110" and t.mitre_source == "wazuh"
    assert "pci_dss:11.4" in t.classification
    assert as_utc(t.detected_at).isoformat().startswith("2026-11-20T14:41:02")
    assert "185.220.101.4" in t.body_html and "Failed password" in t.body_html
    # Contexte rattaché : alerte brute conservée avec son empreinte [PDIS IV.2.1.aa]
    raw = db.scalars(select(RawAlert).where(RawAlert.ticket_id == t.id)).one()
    assert len(raw.sha256) == 64 and '"5712"' in raw.payload


def test_notification_minimale(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    n = db.scalars(select(Notification)).one()
    # PDIS IV.2.3.g : la notification ne contient que la référence (et un lien), aucun détail
    assert "ACME-1" in n.content
    assert "brute" not in n.content.lower() and "185.220" not in n.content and "srv-web" not in n.content


def test_dedoublonnage(app, db, world, alert):
    k = world["keys"]["ACME"]
    assert ingest(app, k, alert(ALERT_SSH_BRUTEFORCE)).status_code == 201
    second = alert(ALERT_SSH_BRUTEFORCE)
    second["id"] = "1732113700.4417999"
    r = ingest(app, k, second)
    assert r.status_code == 200 and r.json()["status"] == "merged" and r.json()["occurrences"] == 2
    assert db.scalars(select(Ticket)).all().__len__() == 1
    assert len(db.scalars(select(RawAlert)).all()) == 2


def test_sous_le_seuil_ignore(app, db, world, alert):
    r = ingest(app, world["keys"]["ACME"], alert(ALERT_LOW))
    assert r.status_code == 202 and r.json()["status"] == "ignored"
    assert db.scalars(select(Ticket)).all() == []


def test_mitre_table_si_wazuh_absent(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_NO_MITRE))
    t = db.scalars(select(Ticket)).one()
    assert t.mitre_source == "table" and t.mitre[0]["id"] == "T1110"


def test_mitre_a_completer(app, db, world, alert):
    a = alert(ALERT_NO_MITRE)
    a["rule"]["groups"] = ["custom"]
    ingest(app, world["keys"]["ACME"], a)
    t = db.scalars(select(Ticket)).one()
    assert t.mitre == [] and t.mitre_source == "a_completer"


def test_criticite_critique(app, db, world, alert):
    ingest(app, world["keys"]["DELTA"], alert(ALERT_CRITICAL))
    t = db.scalars(select(Ticket)).one()
    assert t.ref == "DELTA-1" and t.criticite_initiale == "Critique" and t.importance == "vital"


def test_xss_neutralise(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_XSS))
    t = db.scalars(select(Ticket)).one()
    assert "<script" not in t.body_html and "<img" not in t.body_html
    assert "&lt;script&gt;" in t.body_html


def test_cle_invalide_refusee(app, world, alert):
    r = ingest(app, "kx_faux", alert(ALERT_SSH_BRUTEFORCE))
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")  # RFC 9457


def test_alerte_mal_formee(app, world):
    r = ingest(app, world["keys"]["ACME"], {"pas": "une alerte"})
    assert r.status_code == 422 and r.json()["status"] == 422


def test_cle_rattachee_au_bon_client(app, db, world, alert):
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    t = db.scalars(select(Ticket)).one()
    assert t.ref == "DELTA-1" and t.tenant_id == world["tenants"]["DELTA"].id


def test_renvoi_meme_alerte_idempotent(app, db, world, alert):
    """Le script Wazuh peut renvoyer une alerte déjà reçue : elle n'est pas comptée deux fois."""
    k = world["keys"]["ACME"]
    ingest(app, k, alert(ALERT_SSH_BRUTEFORCE))
    r = ingest(app, k, alert(ALERT_SSH_BRUTEFORCE))
    assert r.status_code == 200 and r.json()["status"] == "duplicate" and r.json()["occurrences"] == 1


def test_caracteres_de_controle_de_l_alerte(app, db, world, alert):
    """Trouvé par le fuzzing (fuzz/fuzz_alerte_wazuh.py) : un caractère nul ou un retour à la ligne venus de l'alerte
    (donnée non fiable) ne doivent ni faire échouer l'ingestion (PostgreSQL refuse le caractère nul dans un texte) ni
    casser le titre sur plusieurs lignes."""
    a = alert(ALERT_SSH_BRUTEFORCE)
    a["rule"]["description"] = "sshd:\x00 brute\nforce\r\x1b[31m"
    a["agent"]["name"] = "srv\x00-web\n-01\t"
    a["location"] = "/var/log/\x00auth.log"
    a["full_log"] = "Failed\x00 password\x07 for root"
    a["data"]["srcuser"] = "ro\x00ot"
    r = ingest(app, world["keys"]["ACME"], a)
    assert r.status_code == 201, r.text
    t = db.scalars(select(Ticket).where(Ticket.ref == r.json()["ticket"])).one()
    for valeur in (t.title, t.rule_description, t.agent_name, t.body_html):
        assert "\x00" not in valeur and "\x1b" not in valeur and "\x07" not in valeur
    assert "\n" not in t.title and "\r" not in t.title
    assert "sshd: brute force" in t.title and "srv-web -01" in t.title
    raw = db.scalars(select(RawAlert).where(RawAlert.ticket_id == t.id)).one()
    assert "\x00" not in raw.payload and "\\u0000" in raw.payload   # original gardé, échappé par JSON
