"""Contexte Wazuh : lien vers l'alerte, lecture de l'indexeur, conservation comme preuve. [ADR-0021]

[PDIS IV.2.1.aa contexte rattaché ; PRIS VI.5.3.c registre des informations collectées ; PDIS IV.3.8.g cloisonnement ;
PDIS IV.3.9.c journalisation ; PDIS IV.3.9.d à h séparation Admin / opérateurs ; ISO/IEC 27037 ; ADR-0006 secrets]
L'indexeur est le faux indexeur local (tests/fake_indexer.py) : aucun de ces tests ne prouve la compatibilité avec un
vrai Wazuh.
"""
import base64
import hashlib
import json
import logging
import os

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import select

from keryx import wazuh_context as wz
from keryx.api import create_app
from keryx.models import Attachment, AuditEntry, CustodyEvent, Tenant

from . import tsa
from .conftest import ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login
from .fake_indexer import ALERT_ID, HOSTILE_LOG, PASSWORD, USER, FakeIndexer

DASHBOARD = "https://wazuh.exemple/app/data-explorer/discover#?_q=(query:'id:%22{alert_id}%22')&_g=(time:(from:'{from}',to:'{to}'))&agent={agent_id}"
BASIC = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
SECRETS = (PASSWORD, BASIC)


@pytest.fixture
def indexer(tmp_path):
    d = tmp_path / "indexeur"
    d.mkdir()
    fake = FakeIndexer(d).start()
    yield fake
    fake.stop()


@pytest.fixture
def wapp(settings):
    """Application dont la règle de sortie accepte la boucle locale (le faux indexeur écoute sur 127.0.0.1)."""
    settings.wazuh_allow_loopback = True
    return create_app(settings)


def configure(app, db, fake, client="ACME", **extra):
    adm = login(app, db, "admin")
    r = adm.patch(f"/api/v1/admin/clients/{client}", json={
        "wazuh_dashboard_url": DASHBOARD, "wazuh_indexer_url": fake.url, "wazuh_indexer_user": USER,
        "wazuh_indexer_password": PASSWORD, "wazuh_ca_pem": fake.ca_pem, **extra})
    assert r.status_code == 200, r.text
    return adm


def fresh(db):
    db.rollback()   # fin de l'instantané de lecture de la session de test
    db.expire_all()


def audit_rows(db, action):
    fresh(db)
    return db.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.seq)).all()


def fetch(c, before=5, after=5, ref="ACME-1"):
    return c.post(f"/api/v1/tickets/{ref}/wazuh-context", json={"before": before, "after": after})


@pytest.fixture
def ticket(wapp, world, alert):
    ingest(wapp, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    return "ACME-1"


# ---------------------------------------------------------------- désactivé par défaut
def test_fonction_masquee_tant_que_non_configuree(wapp, db, world, ticket, indexer):
    a = login(wapp, db, "analyst_acme")
    assert "wazuh" not in a.get("/api/v1/tickets/ACME-1").json()
    r = fetch(a)
    assert r.status_code == 409 and "pas configuré" in r.json()["detail"]
    view = login(wapp, db, "admin").get("/api/v1/admin/clients").json()["items"][0]
    assert view["wazuh_dashboard_url"] is None and view["wazuh_indexer_url"] is None
    assert view["wazuh_credentials_set"] is False and view["wazuh_context_enabled"] is False and view["wazuh_tls_verify"] is True
    assert indexer.requests == []


def test_adresse_seule_sans_compte_ne_suffit_pas(wapp, db, world, ticket, indexer):
    adm = login(wapp, db, "admin")
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": indexer.url}).status_code == 200
    a = login(wapp, db, "analyst_acme")
    assert "wazuh" not in a.get("/api/v1/tickets/ACME-1").json()
    assert fetch(a).status_code == 409 and indexer.requests == []


# ---------------------------------------------------------------- réglages et secrets
def test_reglages_admin_identifiants_chiffres_et_jamais_renvoyes(wapp, db, world, indexer):
    for who in ("manager", "analyst_acme", "client_acme"):
        r = login(wapp, db, who).patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": indexer.url})
        assert r.status_code == 403, who
    adm = login(wapp, db, "admin")
    r = adm.patch("/api/v1/admin/clients/ACME", json={
        "wazuh_dashboard_url": DASHBOARD, "wazuh_indexer_url": indexer.url + "/", "wazuh_index_pattern": "wazuh-alerts-acme-*",
        "wazuh_indexer_user": USER, "wazuh_indexer_password": PASSWORD, "wazuh_ca_pem": indexer.ca_pem + "\ntexte parasite\n"})
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["wazuh_credentials_set"] is True and view["wazuh_context_enabled"] is True and view["wazuh_link_enabled"] is True
    assert view["wazuh_indexer_url"] == indexer.url and view["wazuh_index_pattern"] == "wazuh-alerts-acme-*"
    assert "parasite" not in view["wazuh_ca_pem"] and view["wazuh_ca_pem"].startswith("-----BEGIN CERTIFICATE-----")
    listing = adm.get("/api/v1/admin/clients").text
    for text in (r.text, listing):
        assert not any(s in text for s in SECRETS) and USER not in text
        assert "wazuh_indexer_user" not in text and "wazuh_indexer_password" not in text
    # Au repos : chiffrés, liés au client (un secret recopié sur un autre client ne se déchiffre pas)
    fresh(db)
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    delta = db.scalars(select(Tenant).where(Tenant.key == "DELTA")).one()
    assert acme.wazuh_indexer_password.startswith("v1:") and PASSWORD not in acme.wazuh_indexer_password
    assert acme.wazuh_indexer_user.startswith("v1:") and USER not in acme.wazuh_indexer_user
    box = wapp.state.box
    assert box.decrypt(acme.wazuh_indexer_password, f"wazuh_indexer_password:{acme.id}") == PASSWORD
    with pytest.raises(InvalidTag):
        box.decrypt(acme.wazuh_indexer_password, f"wazuh_indexer_password:{delta.id}")
    # Audit : noms des champs, hôtes et indicateurs ; jamais d'identifiant
    last = audit_rows(db, "client.update")[-1]
    dumped = json.dumps(last.details)
    assert last.details["wazuh"]["indexeur"] == f"127.0.0.1:{indexer.port}" and last.details["wazuh"]["identifiants"] == "definis"
    assert "wazuh_indexer_password" in last.details["champs"]
    assert not any(s in dumped for s in SECRETS) and USER not in dumped
    # Rotation du seul mot de passe ; puis effacement du compte
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_password": "autre-mot-de-passe"}).json()["wazuh_credentials_set"] is True
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_user": None})
    assert r.status_code == 422 and "ensemble" in r.json()["detail"]
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_user": None, "wazuh_indexer_password": None})
    assert r.status_code == 200 and r.json()["wazuh_credentials_set"] is False and r.json()["wazuh_context_enabled"] is False
    # Un champ absent n'efface rien ; les autres réglages du client ne sont pas touchés
    r = adm.patch("/api/v1/admin/clients/ACME", json={"retention_months": 12})
    assert r.json()["wazuh_indexer_url"] == indexer.url and r.json()["wazuh_dashboard_url"] == DASHBOARD


def test_changer_l_adresse_de_l_indexeur_efface_le_compte(wapp, db, world, indexer):
    """Sinon, il suffirait de modifier l'adresse pour faire envoyer le compte enregistré à un autre serveur."""
    adm = configure(wapp, db, indexer)
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": "https://autre-serveur.exemple:9200"})
    assert r.status_code == 200 and r.json()["wazuh_credentials_set"] is False
    assert audit_rows(db, "client.update")[-1].details["wazuh"]["identifiants"] == "effaces"
    # Même adresse renvoyée telle quelle (formulaire complet) : le compte est conservé
    adm = configure(wapp, db, indexer)
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": indexer.url})
    assert r.json()["wazuh_credentials_set"] is True
    # Nouvelle adresse AVEC un nouveau compte : accepté
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": "https://10.1.2.3:9200",
                                                     "wazuh_indexer_user": "lecteur", "wazuh_indexer_password": "x" * 12})
    assert r.status_code == 200 and r.json()["wazuh_credentials_set"] is True
    # Compte sans adresse : refusé
    adm.patch("/api/v1/admin/clients/DELTA", json={})
    r = adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_indexer_user": "lecteur", "wazuh_indexer_password": "x" * 12})
    assert r.status_code == 422 and "adresse" in r.json()["detail"]


@pytest.mark.parametrize("url", [
    "http://indexeur.exemple:9200",                    # pas de HTTPS
    "ftp://indexeur.exemple",
    "https://lecteur:motdepasse@indexeur.exemple:9200",  # identifiants dans l'adresse
    "https://indexeur.exemple:9200/?x=1", "https://indexeur.exemple:9200/#f",
    "https://169.254.169.254", "https://169.254.10.1:9200",     # lien local, métadonnées
    "https://[fe80::1]:9200", "https://[::ffff:169.254.169.254]", "https://[fd00:ec2::254]",
    "https://metadata.google.internal", "https://100.100.100.200",
    "https://127.0.0.1:9200", "https://localhost:9200", "https://[::1]:9200", "https://[::ffff:127.0.0.1]:9200",  # boucle locale
    "https://0.0.0.0:9200", "https://224.0.0.1", "https://255.255.255.255", "https://240.0.0.1",
    "https://indexeur exemple", "https://indexeur.exemple\\@autre", "https://:9200", "https://indexeur.exemple:99999",
    "https://indexeur.exemple/a/../b", "https://nom_invalide.exemple",
])
def test_adresse_d_indexeur_refusee(app, db, world, url):
    """Règle de sortie (ADR-0021) : HTTPS, pas d'identifiants, ni lien local, ni métadonnées, ni boucle locale par défaut."""
    adm = login(app, db, "admin")
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": url, "wazuh_indexer_user": USER,
                                                     "wazuh_indexer_password": PASSWORD})
    assert r.status_code == 422, (url, r.text)
    assert PASSWORD not in r.text and "motdepasse" not in r.text
    view = adm.get("/api/v1/admin/clients").json()["items"][0]
    assert view["wazuh_indexer_url"] is None and view["wazuh_credentials_set"] is False     # rien n'est appliqué


@pytest.mark.parametrize("url", ["https://10.1.2.3:9200", "https://wazuh-indexer.interne:9200", "https://192.168.1.10/indexeur",
                                 "https://[fd12:3456::1]:9200", "https://indexeur.exemple"])
def test_adresse_privee_acceptee(app, db, world, url):
    """Un indexeur Wazuh vit normalement sur un réseau interne : les adresses privées ne sont pas refusées."""
    adm = login(app, db, "admin")
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": url})
    assert r.status_code == 200 and r.json()["wazuh_indexer_url"] == url


@pytest.mark.parametrize("url", [
    "http://wazuh.exemple/app/discover?id={alert_id}", "javascript:alert('{alert_id}')",
    "https://moi:secret@wazuh.exemple/?id={alert_id}", "https://{alert_id}.exemple/", "https://wazuh.exemple:{alert_id}/",
    "https://wazuh.exemple/app/discover#/doc/wazuh-alerts-*/{index}?id={alert_id}",     # {index} : inconnu de Keryx
    "https://wazuh.exemple/{inconnue}", "https://wazuh.exemple/{alert_id", "https://wazuh.exemple/sans-variable",
    "https://wazuh.exemple/a b?id={alert_id}", "https:///chemin?id={alert_id}",
])
def test_modele_d_url_du_tableau_de_bord_refuse(app, db, world, url):
    adm = login(app, db, "admin")
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_dashboard_url": url})
    assert r.status_code == 422, (url, r.text)
    assert "secret" not in r.text
    assert adm.get("/api/v1/admin/clients").json()["items"][0]["wazuh_dashboard_url"] is None


def test_autres_reglages_refuses(app, db, world):
    adm = login(app, db, "admin")
    for body in ({"wazuh_index_pattern": "wazuh-alerts-*,autre-*"}, {"wazuh_index_pattern": "distant:wazuh-*"},
                 {"wazuh_index_pattern": "_all"}, {"wazuh_index_pattern": "a/b"},
                 {"wazuh_ca_pem": "pas un certificat"},
                 {"wazuh_ca_pem": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"},
                 {"wazuh_indexer_url": "https://10.1.2.3:9200", "wazuh_indexer_user": "a:b", "wazuh_indexer_password": "x" * 12},
                 {"wazuh_indexer_url": "https://10.1.2.3:9200", "wazuh_indexer_user": "lecteur", "wazuh_indexer_password": "ligne\nsuivante"}):
        r = adm.patch("/api/v1/admin/clients/ACME", json=body)
        assert r.status_code == 422, (body, r.text)
    # Un mot de passe trop long est refusé sans être recopié dans l'erreur
    long_password = "MOTDEPASSE-" + "z" * 300
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": "https://10.1.2.3:9200",
                                                     "wazuh_indexer_user": "lecteur", "wazuh_indexer_password": long_password})
    assert r.status_code == 422 and "MOTDEPASSE" not in r.text


def test_regle_de_sortie_sur_les_adresses():
    for a in ("169.254.169.254", "169.254.0.1", "fe80::1", "fe80::1%eth0", "::ffff:169.254.169.254", "100.100.100.200",
              "fd00:ec2::254", "0.0.0.0", "0.1.2.3", "::", "224.0.0.1", "ff02::1", "240.0.0.1", "255.255.255.255",
              "127.0.0.1", "127.8.8.8", "::1", "::ffff:127.0.0.1", "2002:a9fe:a9fe::1", "64:ff9b::a9fe:a9fe", "pas-une-ip"):
        assert wz.address_refusal(a) is not None, a
    for a in ("10.0.0.5", "172.16.3.4", "192.168.1.1", "fd12:3456::1", "8.8.8.8", "2001:4860:4860::8888", "100.64.1.1"):
        assert wz.address_refusal(a) is None, a
    assert wz.address_refusal("127.0.0.1", allow_loopback=True) is None and wz.address_refusal("::1", allow_loopback=True) is None
    assert wz.address_refusal("169.254.169.254", allow_loopback=True) is not None     # la dérogation ne couvre que la boucle locale


def test_nom_qui_resout_vers_une_adresse_interdite(wapp, db, world, ticket, monkeypatch):
    """Un nom accepté à la saisie peut pointer plus tard vers une adresse interdite (DNS) : le contrôle porte sur les
    adresses résolues au moment de l'appel, et aucune connexion n'est tentée."""
    adm = login(wapp, db, "admin")
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": "https://indexeur.exemple:9200",
                                                        "wazuh_indexer_user": USER, "wazuh_indexer_password": PASSWORD}).status_code == 200
    import socket
    resolved = {"indexeur.exemple": ["10.0.0.5", "169.254.169.254"]}
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kw):
        if host not in resolved:
            return real(host, port, *args, **kw)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in resolved[host]]
    monkeypatch.setattr(wz.socket, "getaddrinfo", getaddrinfo)
    connections = []
    monkeypatch.setattr(wz.socket, "create_connection", lambda *a, **kw: connections.append(a) or (_ for _ in ()).throw(OSError("interdit")))
    a = login(wapp, db, "analyst_acme")
    r = fetch(a)
    assert r.status_code == 502 and "règle de sortie" in r.json()["detail"] and "lien local" in r.json()["detail"]
    assert connections == []                                    # une seule adresse refusée suffit : aucune connexion
    assert audit_rows(db, "ticket.wazuh_context_failed")[-1].details["erreur"] == "adresse_refusee"
    resolved["indexeur.exemple"] = ["127.0.0.1"]                # boucle locale : acceptée ici (dérogation de test)…
    assert fetch(a).status_code == 503 and len(connections) == 1
    wapp.state.settings.wazuh_allow_loopback = False            # … refusée sans la dérogation
    assert fetch(a).status_code == 502 and len(connections) == 1


def test_boucle_locale_refusee_des_que_la_derogation_est_retiree(wapp, db, world, ticket, indexer):
    configure(wapp, db, indexer)
    a = login(wapp, db, "analyst_acme")
    assert fetch(a).status_code == 200
    seen = len(indexer.requests)
    wapp.state.settings.wazuh_allow_loopback = False
    r = fetch(a)
    assert r.status_code == 409 and "boucle locale" in r.json()["detail"] and len(indexer.requests) == seen


# ---------------------------------------------------------------- lien vers l'alerte
def test_lien_de_l_alerte_pour_l_equipe_seulement(wapp, db, world, ticket, indexer, alert):
    configure(wapp, db, indexer)
    for who in ("analyst_acme", "manager"):
        w = login(wapp, db, who).get("/api/v1/tickets/ACME-1").json()["wazuh"]
        assert w["context"] is True
        assert w["alert_url"].startswith("https://wazuh.exemple/app/data-explorer/discover#?_q=(query:'id:%22" + ALERT_ID + "%22')")
        assert "from:'2026-11-20T14%3A36%3A02.118Z'" in w["alert_url"] and "to:'2026-11-20T14%3A46%3A02.118Z'" in w["alert_url"]
        assert w["alert_url"].endswith("&agent=003")
    client = login(wapp, db, "client_acme")
    body = client.get("/api/v1/tickets/ACME-1")
    assert "wazuh" not in body.json() and "wazuh.exemple" not in body.text       # jamais montré au client
    assert "wazuh.exemple" not in client.get("/api/v1/tickets").text
    assert login(wapp, db, "admin").get("/api/v1/tickets/ACME-1").status_code == 403   # l'Admin règle l'accès, il ne lit rien
    assert login(wapp, db, "analyst_delta").get("/api/v1/tickets/ACME-1").status_code == 404
    # Le client DELTA n'est pas réglé : rien pour son équipe
    ingest(wapp, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    assert "wazuh" not in login(wapp, db, "analyst_delta").get("/api/v1/tickets/DELTA-1").json()


def test_lien_jamais_construit_avec_une_valeur_douteuse(wapp, db, world, indexer, alert):
    """L'identifiant vient de l'alerte (donnée non fiable) : hors du jeu de caractères attendu, aucun lien."""
    configure(wapp, db, indexer)
    hostile = alert(ALERT_SSH_BRUTEFORCE)
    hostile["id"] = "1')),evil:(x:'"
    ingest(wapp, world["keys"]["ACME"], hostile)
    without_id = alert(ALERT_NO_MITRE)
    del without_id["id"]
    ingest(wapp, world["keys"]["ACME"], without_id)
    a = login(wapp, db, "analyst_acme")
    for ref in ("ACME-1", "ACME-2"):
        w = a.get(f"/api/v1/tickets/{ref}").json()["wazuh"]
        assert w["alert_url"] is None and w["context"] is True
    tpl = "https://wazuh.exemple/x?id={alert_id}&a={agent_id}&r={rule_id}&i={index_pattern}&t={timestamp}"
    assert wz.validate_dashboard_template(tpl) == tpl
    link = wz.alert_link(tpl, alert_id="1.2", agent_id="0 0/3", rule_id="5712", when=None, index_pattern=None)
    assert link is None                                           # {timestamp} demandé mais date inconnue
    link = wz.alert_link("https://wazuh.exemple/x?id={alert_id}&a={agent_id}&i={index_pattern}", alert_id="1.2", agent_id="0 0/3",
                         rule_id="5712", when=None, index_pattern=None)
    assert link == "https://wazuh.exemple/x?id=1.2&a=&i=wazuh-alerts-%2A"


# ---------------------------------------------------------------- lecture de l'indexeur
def test_contexte_du_meme_agent_autour_de_l_alerte(wapp, db, world, ticket, indexer, settings):
    configure(wapp, db, indexer)
    a = login(wapp, db, "analyst_acme")
    r = fetch(a, before=5, after=10)
    assert r.status_code == 200, r.text
    out = r.json()
    doc = out["document"]
    assert len(doc["before"]) == 5 and len(doc["after"]) == 10
    entries = doc["before"] + doc["after"]
    assert {e["agent_id"] for e in entries} == {"003"}                      # le même agent, uniquement
    assert "SECRET-AUTRE-AGENT" not in r.text and "pc-rh-03" not in r.text
    # avant = les 5 plus récents avant l'alerte ; après = les 10 plus anciens après ; ordre chronologique ; dates en UTC
    assert [e["full_log"] for e in doc["before"]] == [f"sshd[2211]: avant {i} srv-web-01" for i in (5, 4, 3, 2, 1)]
    assert [e["timestamp"] for e in doc["before"]] == [f"2026-11-20T14:40:{s}.118Z" for s in ("12", "22", "32", "42", "52")]
    assert doc["after"][0]["timestamp"] == "2026-11-20T14:41:12.118Z" and doc["after"][-1]["full_log"] == "sshd[2211]: après 10 srv-web-01"
    assert all(e["timestamp"].endswith("Z") for e in entries)
    # l'alerte d'origine : affichée à part (copie conservée par Keryx), jamais répétée dans la liste
    assert doc["alert"] == {"id": ALERT_ID, "timestamp": "2026-11-20T14:41:02.118Z", "origin": "alerte brute conservée"}
    assert doc["alert_entry"]["id"] == ALERT_ID and "Failed password" in doc["alert_entry"]["full_log"]
    assert ALERT_ID not in [e["id"] for e in entries]
    assert doc["requested"] == {"before": 5, "after": 10} and doc["fetched_by"] == "analyst_acme" and doc["ticket"] == "ACME-1"
    assert doc["source"] == {"indexer": f"127.0.0.1:{indexer.port}", "index_pattern": "wazuh-alerts-*", "time_field": "@timestamp",
                             "agent_id": "003", "tls_verified": True}
    assert out["sha256"] == hashlib.sha256(wz.document_bytes(doc)).hexdigest() and len(out["token"]) == 64
    # assaini : texte pur, sans caractère de contrôle ni marque de sens d'écriture ; le balisage reste du texte
    hostile = doc["after"][0]["full_log"]
    assert "<script>alert(1)</script>" in hostile and "\\x1b" in hostile and "\\x00" in hostile
    assert not any(c in hostile for c in ("\x1b", "\x00", "\u202e")) and HOSTILE_LOG != hostile
    assert all(isinstance(v, (str, type(None))) for e in entries for k, v in e.items() if k != "data")
    assert doc["before"][0]["data"] == {"srcip": "185.220.101.4", "srcuser": "root"}
    # ce que l'indexeur a reçu : deux recherches bornées à l'agent, autour de l'instant de l'alerte
    assert [x["path"] for x in indexer.requests] == ["/wazuh-alerts-*/_search?ignore_unavailable=true&allow_no_indices=true"] * 2
    before_q, after_q = indexer.searches()
    assert before_q["size"] == 5 and after_q["size"] == 11
    for q, op, order in ((before_q, "lt", "desc"), (after_q, "gte", "asc")):
        term, rng = q["query"]["bool"]["filter"]
        assert term == {"term": {"agent.id": "003"}}
        assert rng == {"range": {"@timestamp": {op: "2026-11-20T14:41:02.118Z", "format": "strict_date_optional_time"}}}
        assert q["sort"] == [{"@timestamp": {"order": order, "unmapped_type": "date"}}]
    assert all(x["headers"]["Authorization"] == f"Basic {BASIC}" for x in indexer.requests)
    # audit : qui, quel ticket, quelle fenêtre, combien ; jamais le contenu
    row = audit_rows(db, "ticket.wazuh_context")[-1]
    assert row.actor == "analyst_acme" and row.object_id == "ACME-1" and row.tenant_id == world["tenants"]["ACME"].id
    assert row.details == {"before": 5, "after": 10, "resultats": 15, "avant": 5, "apres": 10, "ecartes": 0}
    # afficher n'écrit rien d'autre : ni pièce, ni fichier
    assert db.scalars(select(Attachment)).all() == []
    assert not os.path.exists(settings.attachments_dir) or not any(files for _, _, files in os.walk(settings.attachments_dir))


def test_motif_d_index_du_client_et_fenetres_autorisees(wapp, db, world, ticket, indexer):
    configure(wapp, db, indexer, wazuh_index_pattern="wazuh-alerts-4.x-*")
    a = login(wapp, db, "manager")
    for before, after in ((5, 5), (10, 15), (15, 5)):
        doc = fetch(a, before, after).json()["document"]
        assert (len(doc["before"]), len(doc["after"])) == (before, after)
    assert indexer.requests[0]["path"].startswith("/wazuh-alerts-4.x-*/_search")
    # un motif qui ne correspond à aucun index : jeu vide, pas une erreur
    configure(wapp, db, indexer, wazuh_index_pattern="autre-*")
    doc = fetch(a).json()["document"]
    assert doc["before"] == [] and doc["after"] == [] and doc["alert_entry"]["id"] == ALERT_ID


def test_serveur_qui_ferme_la_connexion_apres_chaque_reponse(wapp, db, world, ticket, indexer, monkeypatch):
    """« Connection: close » : la seconde recherche repart sur une connexion ouverte et contrôlée par Keryx, jamais sur
    une reconnexion automatique de la bibliothèque HTTP (qui referait une résolution de nom hors de la règle de sortie)."""
    configure(wapp, db, indexer)
    indexer.close_after_reply = True
    checked = []
    real = wz.resolve
    monkeypatch.setattr(wz, "resolve", lambda endpoint, allow: checked.append(endpoint.label) or real(endpoint, allow))
    r = fetch(login(wapp, db, "analyst_acme"), 10, 10)
    assert r.status_code == 200 and len(r.json()["document"]["before"]) == 10 and len(r.json()["document"]["after"]) == 10
    assert len(indexer.requests) == 2 and len(checked) == 2      # deux connexions, chacune passée par le contrôle des adresses


def test_agent_different_jamais_renvoye_meme_si_l_indexeur_le_fournit(wapp, db, world, ticket, indexer):
    """Défense en profondeur : Keryx ne croit pas l'indexeur sur parole, il refiltre sur l'agent du ticket."""
    configure(wapp, db, indexer)
    indexer.mode = "leak"                                        # le faux indexeur ignore le filtre d'agent
    a = login(wapp, db, "analyst_acme")
    r = fetch(a, 15, 15)
    assert r.status_code == 200
    doc = r.json()["document"]
    assert {e["agent_id"] for e in doc["before"] + doc["after"]} == {"003"}
    assert "SECRET-AUTRE-AGENT" not in r.text and "pc-rh-03" not in r.text
    assert audit_rows(db, "ticket.wazuh_context")[-1].details["ecartes"] > 0


def test_roles_et_cloisonnement(wapp, db, world, ticket, indexer):
    configure(wapp, db, indexer)
    client = login(wapp, db, "client_acme")
    assert fetch(client).status_code == 403
    assert client.post("/api/v1/tickets/ACME-1/wazuh-context", json={"before": "tout"}).status_code == 403   # le rôle avant le schéma
    assert client.post("/api/v1/tickets/ACME-1/wazuh-context/keep", json={}).status_code == 403
    adm = login(wapp, db, "admin")
    assert fetch(adm).status_code == 403
    assert adm.post("/api/v1/tickets/ACME-1/wazuh-context/keep", json={}).status_code == 403
    assert audit_rows(db, "ticket.access_denied")[-1].details == {"role": "admin", "objet": "contexte_wazuh"}
    other = login(wapp, db, "analyst_delta")                     # analyste sans accès à ce client
    assert fetch(other).status_code == 404
    assert other.post("/api/v1/tickets/ACME-1/wazuh-context/keep",
                      json={"document": {}, "token": "0" * 64, "description": "essai"}).status_code == 404
    from fastapi.testclient import TestClient
    assert TestClient(wapp).post("/api/v1/tickets/ACME-1/wazuh-context", json={"before": 5, "after": 5}).status_code == 401
    assert indexer.requests == []                                # aucun de ces refus n'a atteint l'indexeur


@pytest.mark.parametrize("body", [
    {"before": 7, "after": 5}, {"before": 5, "after": 20}, {"before": 0, "after": 5}, {"before": -5, "after": 5},
    {"before": "5", "after": 5}, {"before": 5.5, "after": 5}, {"before": None, "after": 5}, {"before": 5},
    {"after": 5}, {}, {"before": 5, "after": 5, "agent": "004"}, {"before": 1000, "after": 1000}, {"before": True, "after": 5},
])
def test_fenetres_non_autorisees(wapp, db, world, ticket, indexer, body):
    configure(wapp, db, indexer)
    r = login(wapp, db, "analyst_acme").post("/api/v1/tickets/ACME-1/wazuh-context", json=body)
    assert r.status_code == 422, (body, r.text)
    assert indexer.requests == []


def test_limite_de_debit(settings, db, world, alert, indexer):
    settings.wazuh_allow_loopback, settings.wazuh_context_user_limit = True, 2
    app2 = create_app(settings)
    ingest(app2, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    configure(app2, db, indexer)
    a = login(app2, db, "analyst_acme")
    assert [fetch(a).status_code for _ in range(3)] == [200, 200, 429]
    assert len(indexer.requests) == 4                            # la troisième demande n'a pas atteint l'indexeur


# ---------------------------------------------------------------- indexeur défaillant, secrets
def test_erreurs_de_l_indexeur_messages_propres(wapp, db, world, ticket, indexer, tmp_path, monkeypatch):
    configure(wapp, db, indexer)
    a = login(wapp, db, "analyst_acme")

    def failing(status, reason, words):
        r = fetch(a)
        assert r.status_code == status, (reason, r.text)
        assert r.headers["content-type"].startswith("application/problem+json")
        detail = r.json()["detail"]
        assert words in detail, detail
        assert not any(s in r.text for s in SECRETS) and USER not in r.text and "DETAIL-INTERNE" not in r.text
        assert audit_rows(db, "ticket.wazuh_context_failed")[-1].details == {"before": 5, "after": 5, "erreur": reason}

    indexer.mode = "500"
    failing(502, "statut_500", "erreur (500)")
    indexer.mode = "junk"
    failing(502, "reponse_invalide", "n'est pas celle d'une recherche")
    indexer.mode = "bad_shape"
    failing(502, "reponse_invalide", "n'est pas celle d'une recherche")
    indexer.mode = "huge"
    failing(502, "reponse_trop_grande", "taille admise")
    # redirection : jamais suivie (la cible ne reçoit rien, surtout pas le compte)
    d = tmp_path / "cible"
    d.mkdir()
    target = FakeIndexer(d).start()
    try:
        indexer.mode, indexer.redirect_to = "redirect", target.url + "/wazuh-alerts-*/_search"
        failing(502, "redirection", "redirection")
        assert target.requests == []
    finally:
        target.stop()
    # compte refusé par l'indexeur
    indexer.mode, indexer.password = "ok", "un-autre-mot-de-passe"
    failing(502, "authentification", "refuse le compte de lecture")
    indexer.password = PASSWORD
    # trop lent : délai court
    monkeypatch.setattr(wz, "TOTAL_TIMEOUT_S", 0.6)
    indexer.delay = 1.5
    failing(503, "delai", "délai")
    indexer.delay = 0
    monkeypatch.setattr(wz, "TOTAL_TIMEOUT_S", 8.0)
    assert fetch(a).status_code == 200                           # l'indexeur rétabli répond de nouveau
    # arrêté : injoignable
    indexer.stop()
    failing(503, "injoignable", "injoignable")
    assert db.scalars(select(Attachment)).all() == []


def test_certificat_tls_de_l_indexeur(wapp, db, world, ticket, indexer, tmp_path):
    adm = configure(wapp, db, indexer, wazuh_ca_pem=None)        # sans l'autorité du client : certificat inconnu
    a = login(wapp, db, "analyst_acme")
    r = fetch(a)
    assert r.status_code == 502 and "certificat TLS" in r.json()["detail"]
    assert indexer.requests == []                                # la négociation a échoué : aucune requête, aucun compte envoyé
    assert audit_rows(db, "ticket.wazuh_context_failed")[-1].details["erreur"] == "certificat_refuse"
    # une autre autorité que celle du serveur : refusé aussi
    other = tmp_path / "autre"
    other.mkdir()
    from .fake_indexer import make_pki
    CREDS = {"wazuh_indexer_user": USER, "wazuh_indexer_password": PASSWORD}
    # Changer l'autorité sans ressaisir le compte l'efface : il n'est pas envoyé à un serveur authentifié autrement.
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_ca_pem": make_pki(str(other))})
    assert r.status_code == 200 and r.json()["wazuh_credentials_set"] is False
    assert audit_rows(db, "client.update")[-1].details["wazuh"]["identifiants"] == "effaces"
    assert fetch(a).status_code == 409
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_ca_pem": make_pki(str(other)), **CREDS}).status_code == 200
    assert fetch(a).status_code == 502
    # la bonne autorité : accepté
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_ca_pem": indexer.ca_pem, **CREDS}).status_code == 200
    assert fetch(a).status_code == 200
    # vérification désactivée (déconseillé, tracé) : accepté sans autorité, et inscrit dans le jeu
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_tls_verify": False})
    assert r.json()["wazuh_credentials_set"] is False            # contrôle TLS retiré : compte effacé aussi
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_ca_pem": None, "wazuh_tls_verify": False, **CREDS})
    assert r.json()["wazuh_tls_verify"] is False
    assert audit_rows(db, "client.update")[-1].details["wazuh"]["verification_tls"] is False
    assert fetch(a).json()["document"]["source"]["tls_verified"] is False


def test_identifiants_jamais_exposes_ni_journalises(wapp, db, world, ticket, indexer, caplog):
    caplog.set_level(logging.DEBUG)
    configure(wapp, db, indexer)
    a = login(wapp, db, "analyst_acme")
    texts = [fetch(a).text, a.get("/api/v1/tickets/ACME-1").text]
    for mode in ("500", "junk", "redirect", "leak"):
        indexer.mode = mode
        texts.append(fetch(a).text)
    indexer.mode, indexer.password = "ok", "change"
    texts.append(fetch(a).text)
    indexer.stop()
    texts.append(fetch(a).text)
    texts.append(login(wapp, db, "admin").get("/api/v1/admin/clients").text)
    fresh(db)
    texts.append(json.dumps([[e.action, e.object_id, e.details] for e in db.scalars(select(AuditEntry))]))
    texts.append(caplog.text)
    assert "Contexte Wazuh : lecture de l'indexeur du client ACME en échec" in caplog.text    # l'échec est journalisé, sobrement
    for text in texts:
        assert not any(s in text for s in SECRETS), text[:300]
    assert USER not in caplog.text and "Authorization" not in caplog.text
    assert "IndexerConfig" not in caplog.text
    cfg = wz.IndexerConfig(endpoint=wz.Endpoint("h", 9200), username=USER, password=PASSWORD)
    assert PASSWORD not in repr(cfg) and USER not in repr(cfg)


# ---------------------------------------------------------------- conservation comme preuve
def keep(c, out, ref="ACME-1", **extra):
    return c.post(f"/api/v1/tickets/{ref}/wazuh-context/keep", json={
        "document": out["document"], "token": out["token"], "description": "Contexte de l'alerte SSH", **extra})


def test_conserver_comme_preuve(wapp, db, world, ticket, indexer, settings):
    configure(wapp, db, indexer)
    a = login(wapp, db, "analyst_acme")
    out = fetch(a, 5, 10).json()
    # Le jeu fait l'aller-retour par le navigateur (JSON) : c'est la forme relue qui est renvoyée
    r = keep(a, json.loads(json.dumps(out)))
    assert r.status_code == 201, r.text
    piece = r.json()
    assert piece["sha256"] == out["sha256"] and piece["visible_client"] is False and piece["kind"] == "fichier"
    assert piece["method"].startswith("Extraction indexeur Wazuh : API _search sur 127.0.0.1:")
    assert "agent 003" in piece["method"] and "5 avant et 10 après" in piece["method"] and ALERT_ID in piece["method"]
    assert piece["sensitivity"] == "TLP:AMBER" and piece["lifecycle"] == "conserve"
    assert piece["collected_at"] == out["document"]["fetched_at"] and piece["collected_at"].endswith("Z")     # date de lecture, UTC
    assert piece["filename"].startswith("contexte-wazuh-ACME-1-") and piece["filename"].endswith("Z.json")
    assert piece["description"] == "Contexte de l'alerte SSH" and piece["scan_status"] == "non_analyse"
    # stockée comme toute pièce ; son contenu a bien l'empreinte annoncée et c'est le jeu lu
    fresh(db)
    row = db.scalars(select(Attachment)).one()
    assert row.tenant_id == world["tenants"]["ACME"].id and row.storage_name and row.content_type == "application/json"
    content = a.get(f"/api/v1/attachments/{piece['id']}/content", params={"motif": "relecture de la preuve"})
    assert content.status_code == 200 and hashlib.sha256(content.content).hexdigest() == out["sha256"]
    assert json.loads(content.content) == out["document"]
    assert a.get(f"/api/v1/attachments/{piece['id']}/content").status_code == 422      # motif obligatoire, comme toute pièce
    # registre de collecte, chaîne de possession, registre des actions, audit
    fresh(db)
    assert [c.action for c in db.scalars(select(CustodyEvent).order_by(CustodyEvent.ts))] == ["depot", "telechargement"]
    events = a.get("/api/v1/tickets/ACME-1").json()["events"]
    assert any(e["action"] == "piece_jointe" and e["details"]["origine"] == "indexeur Wazuh" and e["details"]["sha256"] == out["sha256"] for e in events)
    row = audit_rows(db, "ticket.wazuh_context_keep")[-1]
    assert row.details == {"piece": piece["id"], "sha256": out["sha256"], "before": 5, "after": 10, "resultats": 15}
    assert row.actor == "analyst_acme" and row.tenant_id == world["tenants"]["ACME"].id
    assert "sshd" not in json.dumps(row.details)
    # jamais visible du client
    client = login(wapp, db, "client_acme")
    seen = client.get("/api/v1/tickets/ACME-1")
    assert seen.json()["attachments"] == [] and "contexte-wazuh" not in seen.text and out["sha256"] not in seen.text
    assert client.get(f"/api/v1/attachments/{piece['id']}/content", params={"motif": "essai"}).status_code == 404
    assert login(wapp, db, "analyst_delta").get(f"/api/v1/attachments/{piece['id']}/content", params={"motif": "essai"}).status_code == 404
    # deux fois le même jeu : refusé
    assert keep(a, out).status_code == 409
    # même cycle de vie que les autres pièces : destruction par le manager, contenu supprimé, ligne conservée
    m = login(wapp, db, "manager")
    assert m.post(f"/api/v1/attachments/{piece['id']}/lifecycle", json={"lifecycle": "detruit", "reason": "fin de prestation"}).status_code == 200
    assert not any(files for _, _, files in os.walk(settings.attachments_dir))


def test_conservation_refusee_si_le_jeu_n_est_pas_celui_lu_par_keryx(wapp, db, world, ticket, indexer, alert, monkeypatch):
    configure(wapp, db, indexer)
    a = login(wapp, db, "analyst_acme")
    out = fetch(a).json()
    # contenu modifié dans le navigateur
    forged = json.loads(json.dumps(out))
    forged["document"]["before"][0]["full_log"] = "ligne fabriquée"
    r = keep(a, forged)
    assert r.status_code == 409 and "récupérez-le de nouveau" in r.json()["detail"]
    assert audit_rows(db, "ticket.wazuh_context_keep_refused")[-1].details == {"motif": "sceau"}
    forged = json.loads(json.dumps(out))
    forged["document"]["fetched_at"] = "2030-01-01T00:00:00.000Z"
    assert keep(a, forged).status_code == 409
    # jeu d'un autre analyste, ou rejoué sur un autre ticket
    assert keep(login(wapp, db, "manager"), out).status_code == 409
    other = alert(ALERT_NO_MITRE)
    ingest(wapp, world["keys"]["ACME"], other)
    assert keep(a, out, ref="ACME-2").status_code == 409
    # corps invalides
    for body in ({"document": out["document"], "token": "zz", "description": "abc"},
                 {"document": out["document"], "token": out["token"], "description": "x"},
                 {"document": "texte", "token": out["token"], "description": "abc"},
                 {"document": out["document"], "token": out["token"], "description": "abc", "visible_client": True}):
        assert a.post("/api/v1/tickets/ACME-1/wazuh-context/keep", json=body).status_code == 422
    assert keep(a, out, sensitivity="TLP:ROSE").status_code == 422
    # trop ancien
    monkeypatch.setattr(wz, "TOKEN_TTL", wz.timedelta(seconds=-1))
    r = keep(a, out)
    assert r.status_code == 409 and "30 minutes" in r.json()["detail"]
    monkeypatch.undo()
    fresh(db)
    assert db.scalars(select(Attachment)).all() == []           # aucun de ces refus n'a rien enregistré
    # ticket clos : la lecture reste possible, la conservation non (chaîne de possession figée)
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    assert a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."}).status_code == 200
    closed = fetch(a)
    assert closed.status_code == 200 and keep(a, closed.json()).status_code == 409


def test_sensibilite_choisie_et_alerte_brute_non_conservee(wapp, db, world, ticket, indexer):
    """Sans alerte brute (rétention), la date du ticket sert de pivot et la ligne de l'alerte vient du ticket."""
    from keryx.models import RawAlert
    configure(wapp, db, indexer)
    fresh(db)
    for r in db.scalars(select(RawAlert)).all():
        db.delete(r)
    db.commit()
    a = login(wapp, db, "analyst_acme")
    w = a.get("/api/v1/tickets/ACME-1").json()["wazuh"]
    assert w == {"alert_url": None, "context": True}             # plus d'identifiant d'alerte : pas de lien
    out = fetch(a).json()
    doc = out["document"]
    assert doc["alert"] == {"id": "", "timestamp": "2026-11-20T14:41:02.118Z", "origin": "ticket (alerte brute non conservée)"}
    assert doc["alert_entry"]["rule_id"] == "5712" and doc["alert_entry"]["timestamp"] == "2026-11-20T14:41:02.118Z"
    assert len(doc["before"]) == 5 and len(doc["after"]) == 5    # sans identifiant, l'alerte indexée compte parmi les « après »
    r = keep(a, out, sensitivity="TLP:RED")
    assert r.status_code == 201 and r.json()["sensitivity"] == "TLP:RED" and "l'alerte du ticket" in r.json()["method"]


@pytest.mark.skipif(not tsa.have_openssl(), reason="openssl requis pour l'autorité d'horodatage de test")
def test_la_piece_conservee_s_horodate_comme_les_autres(settings, db, world, alert, indexer, tmp_path):
    d = tmp_path / "tsa"
    d.mkdir()
    ca = tsa.make_pki(d)
    srv = tsa.Tsa(d)
    try:
        settings.wazuh_allow_loopback, settings.tsa_url, settings.tsa_ca_file = True, srv.url, ca
        app2 = create_app(settings)
        ingest(app2, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
        configure(app2, db, indexer)
        a = login(app2, db, "analyst_acme")
        piece = keep(a, fetch(a).json()).json()
        r = a.post(f"/api/v1/attachments/{piece['id']}/timestamp")
        assert r.status_code == 201 and r.json()["gen_time"].endswith("Z")
        assert a.post(f"/api/v1/timestamps/{r.json()['id']}/verify").json()["valid"] is True
    finally:
        srv.stop()


# ---------------------------------------------------------------- assainissement
def test_assainissement_des_evenements():
    assert wz.clean_text("a\x00b\x1b[0m\u202ec\ud800", 100) == "a\\x00b\\x1b[0m\ufffdc\ufffd"
    assert wz.clean_text("l1\nl2\tx", 100, multiline=True) == "l1\nl2\tx" and wz.clean_text("l1\nl2", 100) == "l1\\x0al2"
    assert wz.clean_text({"a": 1}, 10) == "" and wz.clean_text(["x"], 10) == "" and wz.clean_text(None, 10) == ""
    assert wz.clean_text(12, 10) == "12" and wz.clean_text(True, 10) == "true" and len(wz.clean_text("x" * 500, 40)) == 40
    e = wz.entry_from_source({
        "@timestamp": "pas une date", "id": ["liste"], "rule": "texte", "agent": {"id": 3, "name": {"x": 1}},
        "full_log": "x" * 20000, "data": {"win": {"eventdata": {"image": "C:\\a.exe", "<b>clé</b>": "v"}}, "liste": ["a", {"b": 1}, 2],
                                          "profond": {"a": {"b": {"c": {"d": {"e": {"f": {"g": "trop"}}}}}}}}})
    assert e["timestamp"] is None and e["timestamp_brut"] == "pas une date" and e["id"] == "" and e["rule_id"] == ""
    assert e["agent_id"] == "3" and e["agent_name"] == "" and len(e["full_log"]) == 8000
    assert e["data"] == {"liste": "a, 2", "win.eventdata._b_cl___b_": "v", "win.eventdata.image": "C:\\a.exe"}
    big = wz.entry_from_source({"data": {f"k{i}": "v" * 1000 for i in range(200)}})
    assert len(big["data"]) == 40 and all(len(v) == 500 for v in big["data"].values())
    # le document signé ne contient que du JSON sûr (aucun demi-codet isolé : il s'encode en UTF-8)
    wz.document_bytes({"x": wz.clean_text("\ud83d", 10)})


# ---------------------------------------------------------------- indexeur partagé entre clients (ADR-0031)
def _autre_manager(indexer, agent="003", manager="wazuh-manager-02", cluster=None):
    """Événements d'un AUTRE manager, sur le même indexeur, avec le même numéro d'agent, aux mêmes instants."""
    for d in [dict(x) for x in indexer.docs if x["_source"]["agent"]["id"] == agent]:
        src = json.loads(json.dumps(d["_source"]))
        src["manager"] = {"name": manager}
        if cluster:
            src["cluster"] = {"name": cluster}
        src["full_log"] = "SECRET-AUTRE-MANAGER " + src["full_log"]
        indexer.docs.append({"_index": d["_index"], "_id": d["_id"] + "-m2", "_source": src})


def test_indexeur_partage_exige_une_source_par_client(wapp, db, world, indexer):
    configure(wapp, db, indexer)                                            # ACME, motif par défaut
    adm = login(wapp, db, "admin")
    base = {"wazuh_indexer_url": indexer.url, "wazuh_indexer_user": USER, "wazuh_indexer_password": PASSWORD,
            "wazuh_ca_pem": indexer.ca_pem}
    # Même indexeur, même motif, sans source : refusé (comme avant)
    r = adm.patch("/api/v1/admin/clients/DELTA", json=base)
    assert r.status_code == 422 and "ACME" in r.text and "source" in r.text
    # Motifs différents mais qui se recouvrent : refusé aussi (autorisé avant ADR-0031)
    r = adm.patch("/api/v1/admin/clients/DELTA", json={**base, "wazuh_index_pattern": "wazuh-alerts-4.x-*"})
    assert r.status_code == 422
    # DELTA règle sa source avant ACME : accepté (réglage client par client), mais la lecture attend ACME
    r = adm.patch("/api/v1/admin/clients/DELTA", json={**base, "wazuh_indexer_source": "manager:wazuh-manager-02"})
    assert r.status_code == 200
    fresh(db)
    delta = db.scalars(select(Tenant).where(Tenant.key == "DELTA")).one()
    assert wz.source_conflict(db, delta) is not None and wz.source_conflict(db, delta, strict=False) is None
    # ACME reprend la même source que DELTA (sans tenir compte de la casse) : refusé ; une autre : accepté
    r = adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_source": "manager:WAZUH-MANAGER-02"})
    assert r.status_code == 422
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_source": "manager:wazuh-manager-01"}).status_code == 200
    # Sources distinctes : accepté ; motifs disjoints : accepté sans source
    assert adm.patch("/api/v1/admin/clients/DELTA", json={**base, "wazuh_indexer_source": "manager:wazuh-manager-02"}).status_code == 200
    assert wz.patterns_overlap("wazuh-alerts-*", "wazuh-alerts-4.x-*") and wz.patterns_overlap("*", "a-*")
    assert not wz.patterns_overlap("acme-alerts-*", "delta-alerts-*") and not wz.patterns_overlap("acme", "delta")
    # Source invalide
    assert adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_indexer_source": "manager:a b"}).status_code == 422
    assert adm.get("/api/v1/admin/clients").json()["items"][1]["wazuh_indexer_source"] in ("manager:wazuh-manager-01", "manager:wazuh-manager-02")


@pytest.mark.parametrize("mode", ["normal", "leak"])
def test_source_ecarte_les_evenements_d_un_autre_manager(wapp, db, world, ticket, indexer, mode):
    """Même numéro d'agent chez un autre manager du même indexeur : jamais montré, que l'indexeur applique le filtre de
    source ou non (mode « fuite » : Keryx revérifie chaque événement reçu)."""
    _autre_manager(indexer)
    configure(wapp, db, indexer, wazuh_indexer_source="manager:wazuh-manager-01")
    indexer.mode = mode
    a = login(wapp, db, "analyst_acme")
    r = fetch(a, 15, 15)
    assert r.status_code == 200, r.text
    assert "SECRET-AUTRE-MANAGER" not in r.text and "SECRET-AUTRE-AGENT" not in r.text
    before = r.json()["document"]["before"]
    # mode normal : l'indexeur filtre, la page est pleine ; mode fuite : Keryx écarte ce que l'indexeur a mêlé
    assert len(before) == 15 if mode == "normal" else 0 < len(before) <= 15


def test_source_par_nom_de_cluster(wapp, db, world, ticket, indexer):
    """Dans un cluster, manager.name est le nœud : la source peut être le nom du cluster."""
    for d in indexer.docs:
        d["_source"]["cluster"] = {"name": "cluster-acme"}
    _autre_manager(indexer, manager="wazuh-node-07", cluster="cluster-delta")
    configure(wapp, db, indexer, wazuh_indexer_source="cluster:cluster-acme")
    r = fetch(login(wapp, db, "analyst_acme"), 15, 15)
    assert r.status_code == 200 and "SECRET-AUTRE-MANAGER" not in r.text and len(r.json()["document"]["before"]) == 15


def test_reglage_anterieur_partage_sans_source_refuse(wapp, db, world, ticket, indexer):
    """Configuration enregistrée avant ADR-0031 (deux clients, même indexeur, motifs qui se recouvrent, sans source) :
    le contexte est refusé au lieu de mêler les événements."""
    configure(wapp, db, indexer, wazuh_index_pattern="wazuh-alerts-*")
    fresh(db)
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    delta = db.scalars(select(Tenant).where(Tenant.key == "DELTA")).one()
    delta.wazuh_indexer_url, delta.wazuh_index_pattern = acme.wazuh_indexer_url, "wazuh-alerts-4.x-*"
    db.commit()
    r = fetch(login(wapp, db, "analyst_acme"))
    assert r.status_code == 409 and "source" in r.text


def test_indexeurs_ecrits_autrement_et_types_de_source(wapp, db, world, indexer):
    """Revue : un même indexeur peut s'écrire de plusieurs façons (adresse IP sous une autre forme, alias DNS) ; les
    adresses ne sont donc plus comparées. Et deux sources de types différents ne s'excluent pas."""
    configure(wapp, db, indexer, wazuh_indexer_source="manager:mgr-acme")
    adm = login(wapp, db, "admin")
    autre = {"wazuh_indexer_url": "https://indexeur-b.example:9200", "wazuh_indexer_user": USER, "wazuh_indexer_password": PASSWORD}
    assert adm.patch("/api/v1/admin/clients/DELTA", json=autre).status_code == 422                  # autre adresse, même motif
    r = adm.patch("/api/v1/admin/clients/DELTA", json={**autre, "wazuh_indexer_source": "cluster:mgr-b"})
    assert r.status_code == 422 and "même type" in r.json()["detail"]                              # types différents
    assert adm.patch("/api/v1/admin/clients/DELTA", json={**autre, "wazuh_indexer_source": "manager:mgr-b"}).status_code == 200
    assert adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_indexer_source": "mgr-b"}).status_code == 422   # sans type
    assert wz.parse_source("cluster:wazuh") == ("cluster", "wazuh") and wz.parse_source("wazuh") is None


def test_reglage_anterieur_se_repare_client_par_client(wapp, db, world, ticket, indexer):
    """Revue : deux clients partagent un indexeur sans source (réglage d'avant ADR-0031). Chacun peut recevoir sa
    source séparément ; la lecture reste refusée tant que les deux ne sont pas réglés, puis fonctionne."""
    configure(wapp, db, indexer)
    fresh(db)
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    delta = db.scalars(select(Tenant).where(Tenant.key == "DELTA")).one()
    delta.wazuh_indexer_url = acme.wazuh_indexer_url
    db.commit()
    adm, a = login(wapp, db, "admin"), login(wapp, db, "analyst_acme")
    assert fetch(a).status_code == 409
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_source": "manager:wazuh-manager-01"}).status_code == 200
    assert fetch(a).status_code == 409                       # DELTA n'a pas encore de source : rien n'est lu
    assert adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_indexer_source": "manager:wazuh-manager-02"}).status_code == 200
    assert fetch(a).status_code == 200


def test_identifiant_et_etat_du_lien_dans_les_details(app, db, world, alert):
    """Préproduction 27/11/2026 : l'équipe voit l'identifiant de l'alerte, et si le lien vers Wazuh n'est pas réglé ;
    le client ne voit ni l'un ni l'autre."""
    from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    f = login(app, db, "analyst_acme").get(f"/api/v1/tickets/{ref}").json()
    assert f["wazuh_alerte"]["id"] and f["wazuh_alerte"]["lien_regle"] is False
    assert "wazuh_alerte" not in login(app, db, "client_acme").get(f"/api/v1/tickets/{ref}").json()
