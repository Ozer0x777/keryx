"""Astreinte et escalade de l'équipe (ADR-0032, partie 2), contre un faux service de webhook en HTTPS : canaux
déclarés par l'Admin (adresse et secret chiffrés, jamais renvoyés), réglages par client du manager, message minimal,
signature, une seule escalade sans action humaine, code de réponse inscrit au registre, règle de sortie."""
import hashlib
import hmac
import json
import ssl
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from keryx import astreinte
from keryx.models import AuditEntry, Notification, OnCallChannel, Ticket, TicketEvent

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login
from .fake_indexer import make_pki


class FakeWebhook:
    def __init__(self, directory):
        make_pki(str(directory))
        self.ca = str(directory / "ca.pem")
        self.requests, self.status = [], 200
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self.send_response(outer.status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(directory / "server.pem"), str(directory / "server.key"))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def json(self, i=-1):
        return json.loads(self.requests[i]["body"])

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def hook(tmp_path, settings):
    d = tmp_path / "pki"
    d.mkdir()
    h = FakeWebhook(d)
    settings.astreinte_allow_loopback, settings.astreinte_ca_file = True, h.ca
    yield h
    h.stop()


def _canal(admin, name, url, kind="webhook_json", **extra):
    r = admin.post("/api/v1/admin/canaux", json={"name": name, "kind": kind, "target": url, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def _setup(app, db, hook, **politique):
    adm = login(app, db, "admin")
    astr = _canal(adm, "astreinte-soc", f"{hook.url}/hooks/astreinte?jeton=SECRET123", secret="cle-de-signature")
    esc = _canal(adm, "escalade-chef", f"{hook.url}/hooks/escalade", kind="webhook_mattermost")
    m = login(app, db, "manager")
    r = m.put("/api/v1/politique/ACME", json={"astreinte_active": True, "astreinte_canal_id": astr["id"],
                                             "escalade_canal_id": esc["id"], **politique})
    assert r.status_code == 200, r.text
    return astr, esc, m


def _ticket(db, ref):
    db.rollback()
    db.expire_all()
    return db.scalars(select(Ticket).where(Ticket.ref == ref)).one()


def test_canal_adresse_et_secret_jamais_renvoyes(app, db, world, settings):
    adm = login(app, db, "admin")
    c = _canal(adm, "soc", "https://chat.example.org/hooks/AbCdEf123456", kind="webhook_mattermost")
    assert c["target"] == "https://chat.example.org/…" and "AbCdEf" not in json.dumps(adm.get("/api/v1/admin/canaux").json())
    row = db.get(OnCallChannel, c["id"])
    assert row.target_enc.startswith("v1:") and "AbCdEf" not in row.target_enc
    aud = db.scalars(select(AuditEntry).where(AuditEntry.action == "astreinte.canal_cree")).one()
    assert "AbCdEf" not in json.dumps(aud.details)
    # adresses refusées dès la saisie
    for bad in ("http://chat.example.org/x", "https://user:pw@chat.example.org/x", "https://chat.example.org/x#f",
                "https://exa mple.org/x"):
        assert adm.post("/api/v1/admin/canaux", json={"name": "x" + str(len(bad)), "kind": "webhook_json", "target": bad}).status_code == 422
    assert adm.post("/api/v1/admin/canaux", json={"name": "mail", "kind": "email", "target": "pas-une-adresse"}).status_code == 422
    assert adm.post("/api/v1/admin/canaux", json={"name": "soc", "kind": "email", "target": "soc@example.org"}).status_code == 409
    assert adm.post("/api/v1/admin/canaux", json={"name": "mm", "kind": "webhook_mattermost", "target": "https://a.example/x",
                                                   "secret": "s"}).status_code == 422


def test_droits(app, db, world):
    for qui in ("manager", "analyst_acme", "client_acme"):
        c = login(app, db, qui)
        assert c.get("/api/v1/admin/canaux").status_code == 403
        assert c.post("/api/v1/admin/canaux", json={"name": "x", "kind": "email", "target": "a@b.fr"}).status_code == 403
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"astreinte_active": True}).status_code == 422     # pas de canal
    assert m.put("/api/v1/politique/ACME", json={"astreinte_canal_id": "inconnu"}).status_code == 422
    assert m.put("/api/v1/politique/ACME", json={"astreinte_criticites": ["Énorme"]}).status_code == 422
    assert m.put("/api/v1/politique/ACME", json={"astreinte_delais": {"Critique": 0}}).status_code == 422


def test_astreinte_puis_une_seule_escalade(app, db, world, alert, hook, settings):
    astr, esc, m = _setup(app, db, hook, astreinte_delais={"Critique": 10})
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    assert _ticket(db, ref).criticite_initiale == "Critique"
    assert len(hook.requests) == 1
    req = hook.requests[0]
    assert req["path"] == "/hooks/astreinte?jeton=SECRET123"
    data = hook.json()
    assert data["type"] == "keryx.astreinte" and data["ticket"] == ref and data["client"] == "ACME"
    assert data["url"] == f"https://keryx.local/tickets/{ref}" and "titre" not in data        # minimisation
    ts, sig = req["headers"]["X-Keryx-Timestamp"], req["headers"]["X-Keryx-Signature"]
    assert sig == "sha256=" + hmac.new(b"cle-de-signature", ts.encode() + b"." + req["body"], hashlib.sha256).hexdigest()
    n = db.scalars(select(Notification).where(Notification.motif == "astreinte")).one()
    assert n.status == "envoye" and n.http_status == 200 and n.recipient == "astreinte-soc" and "SECRET123" not in n.content
    t = _ticket(db, ref)
    assert t.astreinte_at is not None
    # avant le délai : rien ; après : une escalade, une seule, au format Mattermost / Slack
    assert astreinte.tick(_factory(app), settings, now=t.astreinte_at + timedelta(minutes=9))["escalades"] == 0
    later = t.astreinte_at + timedelta(minutes=11)
    assert astreinte.tick(_factory(app), settings, now=later)["escalades"] == 1
    assert astreinte.tick(_factory(app), settings, now=later + timedelta(hours=1))["escalades"] == 0
    assert len(hook.requests) == 2 and hook.requests[1]["path"] == "/hooks/escalade"
    text = hook.json()["text"]
    assert text.startswith("[Keryx] ESCALADE") and ref in text and "10 min" in text and set(hook.json()) == {"text"}
    db.rollback()
    ev = db.scalars(select(TicketEvent).where(TicketEvent.action == "escalade")).one()
    assert ev.actor == "keryx" and not ev.visible_client and ev.details["delai_minutes"] == 10
    # le client ne voit ni l'astreinte ni l'escalade
    vue = login(app, db, "client_acme").get(f"/api/v1/tickets/{ref}").json()
    assert not [e for e in vue["events"] if e["action"] in ("astreinte", "escalade")]


def _factory(app):
    return sessionmaker(bind=app.state.engine)


def test_pas_d_escalade_si_acquitte_ou_criticite_non_choisie(app, db, world, alert, hook, settings):
    _setup(app, db, hook)
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    assert login(app, db, "analyst_acme").post(f"/api/v1/tickets/{ref}/prise-en-charge").status_code == 200
    t = _ticket(db, ref)
    assert astreinte.tick(_factory(app), settings, now=t.astreinte_at + timedelta(hours=2))["escalades"] == 0
    autre = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    assert _ticket(db, autre).criticite_initiale != "Critique"
    assert _ticket(db, autre).astreinte_at is None and len(hook.requests) == 1


def test_echec_inscrit_puis_relance(app, db, world, alert, hook, settings):
    _setup(app, db, hook)
    hook.status = 500
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    n = db.scalars(select(Notification).where(Notification.motif == "astreinte")).one()
    assert n.status == "echec" and n.http_status == 500 and n.attempts == 1
    hook.status = 200
    out = astreinte.tick(_factory(app), settings, now=n.ts + timedelta(minutes=3))
    assert out["relances"] == 1
    db.rollback()
    db.expire_all()
    n = db.get(Notification, n.id)
    assert n.status == "envoye" and n.attempts == 2


def test_regle_de_sortie(settings):
    settings.astreinte_allow_loopback = False
    with pytest.raises(astreinte.DeliveryError) as e:
        astreinte.post(settings, "https://127.0.0.1:9/x", b"{}", {})
    assert e.value.reason == "adresse_refusee"
    with pytest.raises(astreinte.DeliveryError) as e:
        astreinte.post(settings, "https://169.254.169.254/latest", b"{}", {})
    assert e.value.reason == "adresse_refusee"


def test_essai_du_canal(app, db, world, hook):
    adm = login(app, db, "admin")
    c = _canal(adm, "essai", f"{hook.url}/t")
    r = adm.post(f"/api/v1/admin/canaux/{c['id']}/essai")
    assert r.json() == {"statut": "envoye", "code": 200} and hook.json()["type"] == "keryx.essai"
    hook.status = 403
    assert adm.post(f"/api/v1/admin/canaux/{c['id']}/essai").json() == {"statut": "echec", "code": 403, "erreur": "reponse"}
    # canal désactivé : plus proposé au manager
    assert adm.put(f"/api/v1/admin/canaux/{c['id']}", json={"active": False}).json()["active"] is False
    assert login(app, db, "manager").get("/api/v1/politique").json()["canaux"] == []


# ---------------------------------------------------------------- canal courriel (astreinte par courriel de l'équipe)
@pytest.fixture
def smtp(settings, monkeypatch):
    from keryx import notify

    from .test_notifications import FakeSMTP
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    settings.smtp_host = "smtp.example.eu"
    yield FakeSMTP
    FakeSMTP.fail = False


def test_astreinte_et_escalade_par_courriel(app, db, world, alert, smtp, settings):
    adm = login(app, db, "admin")
    astr = _canal(adm, "astreinte-mail", "astreinte@soc.example", kind="email")
    esc = _canal(adm, "chef-de-quart", "chef@soc.example", kind="email")
    assert astr["target"] == "astreinte@soc.example"
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"astreinte_active": True, "astreinte_canal_id": astr["id"],
                                                "escalade_canal_id": esc["id"]}).status_code == 200
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    mails = [x for x in smtp.sent if x["To"] == "astreinte@soc.example"]
    assert len(mails) == 1
    assert mails[0]["Subject"] == f"[Keryx] Astreinte {ref} (Critique, ACME) : nouveau ticket"
    corps = mails[0].get_content()
    assert f"https://keryx.local/tickets/{ref}" in corps and "Correlated exfiltration" not in corps     # pas le titre
    n = db.scalars(select(Notification).where(Notification.motif == "astreinte")).one()
    assert n.status == "envoye" and n.channel == "email" and n.recipient == "astreinte-mail"
    t = _ticket(db, ref)
    assert astreinte.tick(_factory(app), settings, now=t.astreinte_at + timedelta(minutes=16))["escalades"] == 1
    chef = [x for x in smtp.sent if x["To"] == "chef@soc.example"]
    assert len(chef) == 1 and chef[0]["Subject"].startswith(f"[Keryx] ESCALADE {ref} (Critique, ACME)")
    assert "15 min" in chef[0]["Subject"]


def test_courriel_sans_smtp_ou_en_panne(app, db, world, alert, smtp, settings):
    adm = login(app, db, "admin")
    c = _canal(adm, "astreinte-mail", "astreinte@soc.example", kind="email")
    smtp.fail = True
    r = adm.post(f"/api/v1/admin/canaux/{c['id']}/essai").json()
    assert r == {"statut": "echec", "code": None, "erreur": "smtp"}
    smtp.fail = False
    assert adm.post(f"/api/v1/admin/canaux/{c['id']}/essai").json() == {"statut": "envoye", "code": None}
    assert smtp.sent[-1]["Subject"] == "[Keryx] Essai du canal « astreinte-mail »"
    settings.smtp_host = None
    assert adm.post(f"/api/v1/admin/canaux/{c['id']}/essai").json()["erreur"] == "smtp_absent"


def test_format_teams(app, db, world, alert, hook):
    adm = login(app, db, "admin")
    c = _canal(adm, "teams-soc", f"{hook.url}/workflows/abc/triggers/manual/paths/invoke?sig=SIGNATURE", kind="webhook_teams")
    assert c["target"].endswith("/…") and "SIGNATURE" not in c["target"]
    m = login(app, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"astreinte_active": True, "astreinte_canal_id": c["id"]}).status_code == 200
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL)).json()["ticket"]
    body = hook.json()
    assert hook.requests[-1]["path"].endswith("?sig=SIGNATURE") and body["type"] == "message"
    att = body["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][0]["text"] == "[Keryx] Astreinte" and ref in card["body"][1]["text"]
    assert card["actions"] == [{"type": "Action.OpenUrl", "title": "Ouvrir dans Keryx", "url": f"https://keryx.local/tickets/{ref}"}]
    assert "Correlated exfiltration" not in json.dumps(body)        # minimisation : pas de titre par défaut
