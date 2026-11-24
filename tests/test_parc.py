"""Parc d'agents Wazuh (ADR-0030). Le manager est le faux manager local (tests/fake_wazuh_api.py) et l'indexeur le faux
indexeur : aucun de ces tests ne prouve la compatibilité avec un vrai Wazuh (champs, permissions)."""
import csv
import io
from datetime import timedelta

import pytest
from sqlalchemy import select

from keryx import routes_parc
from keryx.api import create_app
from keryx.ids import utcnow
from keryx.models import AuditEntry, Tenant, WazuhAgent, WazuhAgentEvent

from .conftest import login
from .fake_indexer import FakeIndexer
from .fake_indexer import PASSWORD as IDX_PASSWORD
from .fake_indexer import USER as IDX_USER
from .fake_wazuh_api import PASSWORD, USER, FakeWazuhApi


@pytest.fixture
def wapi(tmp_path):
    d = tmp_path / "api"
    d.mkdir()
    fake = FakeWazuhApi(d).start()
    yield fake
    fake.stop()


@pytest.fixture
def papp(settings):
    settings.wazuh_allow_loopback = True
    return create_app(settings)


def configure(app, db, fake, client="ACME", group="acme", **extra):
    adm = login(app, db, "admin")
    r = adm.patch(f"/api/v1/admin/clients/{client}", json={
        "wazuh_api_url": fake.url, "wazuh_api_user": USER, "wazuh_api_password": PASSWORD,
        "wazuh_api_group": group, "wazuh_ca_pem": fake.ca_pem, **extra})
    assert r.status_code == 200, r.text
    return adm


def fresh(db):
    db.rollback()
    db.expire_all()


def by_id(parc):
    return {a["id"]: a for a in parc["agents"]}


def test_reglage_par_l_admin_compte_jamais_relu(papp, db, world, wapi):
    adm = configure(papp, db, wapi)
    c = adm.get("/api/v1/admin/clients").json()["items"]
    acme = next(x for x in c if x["key"] == "ACME")
    assert acme["wazuh_api_credentials_set"] and acme["wazuh_api_group"] == "acme"
    assert PASSWORD not in str(c) and USER not in str(c)
    # Adresse changée sans ressaisir le compte : le compte est effacé (il ne part pas vers un autre serveur)
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_api_url": "https://127.0.0.2:55000"}).status_code == 200
    acme = next(x for x in adm.get("/api/v1/admin/clients").json()["items"] if x["key"] == "ACME")
    assert not acme["wazuh_api_credentials_set"]
    # Adresse refusée (métadonnées), groupe invalide
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_api_url": "https://169.254.169.254/"}).status_code == 422
    assert adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_api_group": "a b"}).status_code == 422


def test_manager_partage_exige_un_groupe_par_client(papp, db, world, wapi):
    adm = configure(papp, db, wapi)
    r = adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_api_url": wapi.url, "wazuh_api_user": USER,
                                                       "wazuh_api_password": PASSWORD, "wazuh_api_group": "acme"})
    assert r.status_code == 422 and "groupe" in r.text
    r = adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_api_url": wapi.url, "wazuh_api_user": USER,
                                                       "wazuh_api_password": PASSWORD})
    assert r.status_code == 422
    assert adm.patch("/api/v1/admin/clients/DELTA", json={"wazuh_api_url": wapi.url, "wazuh_api_user": USER,
                                                          "wazuh_api_password": PASSWORD, "wazuh_api_group": "delta"}).status_code == 200


def test_releve_etats_versions_et_vue_equipe(papp, db, world, wapi):
    configure(papp, db, wapi)
    a = login(papp, db, "analyst_acme")
    r = a.post("/api/v1/parc/ACME/refresh")
    assert r.status_code == 200, r.text and r.json()["agents"] == 6
    p = a.get("/api/v1/parc?client=ACME").json()
    agents = by_id(p)
    assert p["manager_version"] == "4.12.0" and p["configured"] and p["error"] is None
    assert set(agents) == {"001", "002", "003", "004", "005", "006"}          # ni le manager 000, ni l'agent de DELTA
    assert agents["001"]["status"] == "active" and agents["001"]["version_gap"] is None
    assert agents["003"]["version_gap"] == "retard" and agents["002"]["version_gap"] == "tres_ancienne"
    assert agents["002"]["down24"] and not agents["004"]["down24"]               # 50 h contre 2 h
    assert agents["005"]["status"] == "never_connected" and agents["006"]["status"] == "pending"
    assert "node" in agents["001"] and "open_tickets" in agents["001"]
    assert {v["version"]: v["count"] for v in p["versions"]}["4.12.0"] == 3
    # Le dernier contact sert de « déconnecté depuis » à la première observation
    since = agents["002"]["status_since"]
    assert since and since.startswith((utcnow() - timedelta(hours=50)).strftime("%Y-%m-%dT%H"))
    # Requête émise : jeton, filtre de groupe, champs choisis ; jamais d'écriture vers Wazuh
    assert all(x["method"] in ("GET", "POST") for x in wapi.requests)
    assert all(x["path"].split("?")[0] in ("/security/user/authenticate", "/", "/agents") for x in wapi.requests)
    agents_req = [x for x in wapi.requests if x["path"].startswith("/agents")]
    assert "group=acme" in agents_req[0]["path"] and "select=" in agents_req[0]["path"]


def test_filtre_de_groupe_non_cru_sur_parole(papp, db, world, wapi):
    configure(papp, db, wapi)
    wapi.mode = "leak"                                     # le serveur renvoie aussi les agents de DELTA
    a = login(papp, db, "analyst_acme")
    assert a.post("/api/v1/parc/ACME/refresh").status_code == 200
    assert "007" not in by_id(a.get("/api/v1/parc?client=ACME").json())


def test_historique_changements_et_agent_retire(papp, db, world, wapi):
    configure(papp, db, wapi)
    a = login(papp, db, "analyst_acme")
    assert a.post("/api/v1/parc/ACME/refresh").status_code == 200
    for x in wapi.agents:
        if x["id"] == "004":
            x["status"] = "active"                      # reconnecté
    wapi.agents = [x for x in wapi.agents if x["id"] != "005"]      # retiré de Wazuh
    assert a.post("/api/v1/parc/ACME/refresh").status_code == 200
    d = a.get("/api/v1/parc/ACME/agents/004").json()
    assert d["status"] == "active" and [c["status"] for c in d["changes"]][:2] == ["active", "disconnected"]
    assert d["availability_7d"] is not None and abs(sum(s["share"] for s in d["timeline_7d"]) - 1) < 0.01
    assert "005" not in by_id(a.get("/api/v1/parc?client=ACME").json())
    fresh(db)
    assert db.scalars(select(WazuhAgentEvent).where(WazuhAgentEvent.agent_id == "005", WazuhAgentEvent.status == "removed")).first()
    # Un troisième relevé dans la minute est refusé (protège le manager)
    assert a.post("/api/v1/parc/ACME/refresh").status_code == 429


def test_vue_client_reduite_et_cloisonnement(papp, db, world, wapi):
    configure(papp, db, wapi)
    login(papp, db, "analyst_acme").post("/api/v1/parc/ACME/refresh")
    c = login(papp, db, "client_acme")
    p = c.get("/api/v1/parc").json()
    assert p["client"]["key"] == "ACME" and len(p["agents"]) == 6
    assert "node" not in p["agents"][0] and "open_tickets" not in p["agents"][0]
    assert c.get("/api/v1/parc?client=DELTA").status_code == 404
    assert c.post("/api/v1/parc/ACME/refresh").status_code == 403
    assert c.get("/api/v1/parc/ACME/export.csv").status_code == 403
    d = c.get("/api/v1/parc/ACME/agents/002").json()
    assert "tickets" not in d and "node" not in d
    assert login(papp, db, "client_delta").get("/api/v1/parc?client=ACME").status_code == 404
    assert login(papp, db, "admin").get("/api/v1/parc").status_code == 403
    assert login(papp, db, "analyst_acme").get("/api/v1/parc?client=DELTA").status_code == 404


def test_echec_du_releve_message_equipe_indicateur_client(papp, db, world, wapi):
    configure(papp, db, wapi)
    a = login(papp, db, "analyst_acme")
    wapi.mode = "500"
    r = a.post("/api/v1/parc/ACME/refresh")
    assert r.status_code == 502 and "DETAIL-INTERNE" not in r.text
    assert "erreur" in a.get("/api/v1/parc").json()["error"]
    assert login(papp, db, "client_acme").get("/api/v1/parc").json()["error"] is True


def test_mauvais_mot_de_passe_et_redirection(papp, db, world, wapi):
    configure(papp, db, wapi, wazuh_api_password="pas-le-bon-mot-de-passe")
    a = login(papp, db, "analyst_acme")
    r = a.post("/api/v1/parc/ACME/refresh")
    assert r.status_code == 502 and "refuse le compte" in r.json()["detail"]
    fresh(db)
    assert all(PASSWORD not in str(e.details) for e in db.scalars(select(AuditEntry)))


def test_ticket_agent_deconnecte_a_la_main(papp, db, world, wapi):
    configure(papp, db, wapi)
    a = login(papp, db, "analyst_acme")
    a.post("/api/v1/parc/ACME/refresh")
    assert a.post("/api/v1/parc/ACME/agents/001/ticket").status_code == 409        # actif
    r = a.post("/api/v1/parc/ACME/agents/002/ticket")
    assert r.status_code == 201 and r.json()["status"] == "created"
    t = a.get(f"/api/v1/tickets/{r.json()['ref']}").json()
    assert t["rule"]["id"] == "keryx-agent-deconnecte" and t["agent"]["id"] == "002"
    assert a.post("/api/v1/parc/ACME/agents/002/ticket").json()["status"] == "duplicate"   # pas de doublon
    assert login(papp, db, "client_acme").post("/api/v1/parc/ACME/agents/002/ticket").status_code == 403


def test_export_csv(papp, db, world, wapi):
    wapi.agents[1]["name"] = "=HYPERLINK(\"http://x\")"
    configure(papp, db, wapi)
    a = login(papp, db, "analyst_acme")
    a.post("/api/v1/parc/ACME/refresh")
    r = a.get("/api/v1/parc/ACME/export.csv")
    rows = list(csv.reader(io.StringIO(r.text), delimiter=";"))
    assert rows[0][0] == "agent" and len(rows) == 7
    assert any(x[1].startswith("'=") for x in rows[1:])                          # formule neutralisée


def test_silencieux_par_l_indexeur(papp, db, world, tmp_path):
    import datetime as dt
    from .fake_indexer import wazuh_time
    d = tmp_path / "wazuh"
    d.mkdir()
    now = dt.datetime.now(dt.timezone.utc)

    def doc(i, agent, when):
        return {"_index": "wazuh-alerts-4.x-x", "_id": i, "_source": {"@timestamp": when.isoformat().replace("+00:00", "Z"),
                "timestamp": wazuh_time(when), "agent": {"id": agent}, "rule": {"id": "1", "level": 3}}}
    idx = FakeIndexer(d, docs=[doc("e1", "001", now - dt.timedelta(minutes=5)), doc("e2", "003", now - dt.timedelta(days=2)),
                               doc("e3", "007", now)]).start()
    api = FakeWazuhApi(d, reuse_pki=True).start()          # même autorité que l'indexeur, comme chez un client
    try:
        configure(papp, db, api, wazuh_indexer_url=idx.url, wazuh_indexer_user=IDX_USER, wazuh_indexer_password=IDX_PASSWORD)
        a = login(papp, db, "analyst_acme")
        assert a.post("/api/v1/parc/ACME/refresh").status_code == 200
        agents = by_id(a.get("/api/v1/parc").json())
        assert agents["001"]["last_event_at"] and agents["001"]["silent"] is False
        assert agents["003"]["silent"] is True                                  # actif, dernier événement il y a 2 jours
        assert agents["002"]["silent"] is None                                  # déconnecté : la question ne se pose pas
        body = [x for x in idx.searches() if "aggs" in x][0]
        assert set(body["query"]["bool"]["filter"][0]["terms"]["agent.id"]) == {"001", "002", "003", "004", "005", "006"}
    finally:
        api.stop()
        idx.stop()


def test_releve_de_fond(papp, db, world, wapi, settings):
    configure(papp, db, wapi)
    from keryx.db import make_engine, make_session_factory
    from keryx.security import SecretBox
    factory = make_session_factory(make_engine(settings.database_url))
    assert routes_parc.poll_all(factory, settings, SecretBox(settings.secret_key)) == 1
    fresh(db)
    assert db.scalars(select(WazuhAgent)).first() is not None


def test_parc_au_pilotage_et_au_rapport(papp, db, world, wapi):
    configure(papp, db, wapi)
    m = login(papp, db, "manager")
    assert m.post("/api/v1/parc/ACME/refresh").status_code == 200
    d = m.get("/api/v1/dashboard?client=ACME").json()["parc"]
    assert d["agents"] == 6 and d["by_status"]["disconnected"] == 2 and d["down24"] == 1 and d["outdated"] == 2
    assert d["availability_percent"] is not None and d["least_available"][0]["agent"] in ("002", "004")
    r = m.get("/api/v1/reports/period?client=ACME").json()
    assert r["parc"]["agents"] == 6
    assert m.get("/api/v1/dashboard?client=DELTA").json()["parc"] is None         # aucun relevé pour DELTA
