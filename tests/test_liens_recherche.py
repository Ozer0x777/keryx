"""Lier des tickets et les retrouver : éléments relevés dans les alertes (IP, comptes, hôtes, empreintes), recherche
par champ ou en texte libre (description, alerte brute), sens du lien parent, suggestions « peut-être liés »."""
import io
import json
import zipfile

from sqlalchemy import select

from keryx import restitution
from keryx.models import Observable, Tenant, TicketEvent
from keryx.observables import extraire, normaliser

from .conftest import ALERT_NO_MITRE, ALERT_SSH_BRUTEFORCE, ingest, login


def _deux(app, world, alert):
    a = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    autre = alert(ALERT_NO_MITRE)
    autre["data"] = {"src_ip": "185.220.101.4", "dstuser": "Admin", "md5_after": "D41D8CD98F00B204E9800998ECF8427E"}
    b = ingest(app, world["keys"]["ACME"], autre).json()["ticket"]
    return a, b


def test_releve_des_elements():
    e = extraire(ALERT_SSH_BRUTEFORCE)
    assert ("ip", "185.220.101.4") in e and ("ip", "10.20.1.15") in e        # IP du journal brut et de l'agent
    assert ("compte", "root") in e and ("hote", "srv-web-01") in e
    assert extraire({"data": {"sha256": "A" * 64}}) == {("hash", "a" * 64)}
    assert extraire({"data": {"id": "a" * 64}}) == set()                     # une suite hexadécimale quelconque n'est pas une empreinte
    assert normaliser("domaine", "https://Evil.Example.com/x") == "evil.example.com"
    assert normaliser("ip", "0.0.0.0") is None and normaliser("ip", "pas une ip") is None


def test_recherche_par_champ_et_dans_l_alerte_brute(app, db, world, alert):
    a, b = _deux(app, world, alert)
    an = login(app, db, "analyst_acme")
    refs = lambda q, c=an: sorted(t["ref"] for t in c.get("/api/v1/tickets", params={"q": q}).json()["items"])  # noqa: E731
    assert refs("ip:185.220.101.4") == sorted([a, b])
    assert refs("compte:admin") == [b] and refs("hash:d41d8cd98f00b204e9800998ecf8427e") == [b]
    assert refs("regle:5712") == [a] and refs("agent:pc-rh-03") == [b]
    assert refs("51344") == [a]                                    # texte libre : port (description et alerte brute)
    # valeur présente seulement dans l'alerte brute : trouvée par l'équipe, jamais par le client
    assert refs("wazuh-manager-01") == [a]
    assert refs("wazuh-manager-01", login(app, db, "client_acme")) == []
    assert refs("ip:185.220.101.4", login(app, db, "analyst_delta")) == []   # cloisonnement par client


def test_fenetre_de_lien_recherche_et_sens(app, db, world, alert):
    a, b = _deux(app, world, alert)
    an = login(app, db, "analyst_acme")
    r = an.get(f"/api/v1/tickets/{a}/links/search", params={"q": "ip:185.220.101.4"}).json()["items"]
    assert [x["ref"] for x in r] == [b]                            # jamais le ticket lui-même
    assert r[0]["trouve"][0]["ou"] == "alerte" and r[0]["trouve"][0]["champ"] == "data.src_ip"
    # « a est le parent de b » : vu de b, a est son parent
    assert an.post(f"/api/v1/tickets/{a}/links", json={"ref": b, "kind": "parent", "sens": "parent_de"}).status_code == 201
    vu_de_b = an.get(f"/api/v1/tickets/{b}/links").json()["items"]
    assert vu_de_b[0]["kind"] == "parent" and vu_de_b[0]["ref"] == a
    assert an.get(f"/api/v1/tickets/{a}/links").json()["items"][0]["kind"] == "enfant"
    assert an.post(f"/api/v1/tickets/{a}/links", json={"ref": b, "kind": "lie", "sens": "dessous"}).status_code in (409, 422)
    db.rollback()
    assert {e.ticket_id for e in db.scalars(select(TicketEvent).where(TicketEvent.action == "lien"))} and \
        len(db.scalars(select(TicketEvent).where(TicketEvent.action == "lien")).all()) == 2   # au registre des deux tickets
    assert login(app, db, "client_acme").get(f"/api/v1/tickets/{a}/links/search", params={"q": "x"}).status_code == 403


def test_suggestions_et_fusion(app, db, world, alert, settings):
    a, b = _deux(app, world, alert)
    an = login(app, db, "analyst_acme")
    s = an.get(f"/api/v1/tickets/{a}/links/suggestions").json()["items"]
    assert any(x["kind"] == "ip" and x["value"] == "185.220.101.4" and x["tickets"][0]["ref"] == b for x in s)
    an.post(f"/api/v1/tickets/{a}/links", json={"ref": b, "kind": "lie"})
    assert an.get(f"/api/v1/tickets/{a}/links/suggestions").json()["items"] == []      # déjà lié : plus suggéré
    # fusion : les éléments du doublon rejoignent le ticket conservé
    assert an.post(f"/api/v1/tickets/{b}/merge", json={"into": a, "reason": "même attaque"}).status_code == 200
    db.rollback()
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    valeurs = {(o.kind, o.value) for o in db.scalars(select(Observable).where(Observable.tenant_id == acme.id))}
    assert ("compte", "admin") in valeurs
    buf = io.BytesIO()
    restitution.export_client(db, settings, acme, buf)
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as z:
        assert any(o["value"] == "admin" for o in json.loads(z.read("elements-releves.json")))
