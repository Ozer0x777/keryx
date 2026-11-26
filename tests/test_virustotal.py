"""Recherche d'empreinte sur VirusTotal : clé par utilisateur, sources d'empreinte, résultats, traçabilité. [ADR-0022]

[PRIS IV.3.q codes malveillants ; PDIS IV.2.1.q qualification ; PRIS VI.5.3.d registre des actions ; ISO/IEC 27037 ;
PDIS IV.3.8.g cloisonnement ; PDIS IV.3.9.c journalisation ; PDIS IV.3.9.d à h séparation Admin / opérateurs ;
ISO/IEC 27002:2022 8.24 (secrets, via ADR-0006) ; RFC 6585]
VirusTotal est le faux serveur local (tests/fake_virustotal.py) : aucun de ces tests ne prouve la compatibilité avec le
vrai service, et aucun n'y envoie quoi que ce soit.
"""
import hashlib
import io
import json
import logging
import zipfile

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select

from keryx import virustotal as vt
from keryx.api import create_app
from keryx.config import Settings
from keryx.models import AuditEntry, CustodyEvent, HashLookup, Ticket, TicketEvent, User

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login
from .fake_virustotal import (API_KEY, EICAR, EICAR_SHA1, EICAR_SHA256, HOSTILE_SHA256, QUIET_SHA256, UNKNOWN_SHA256,
                              FakeVirusTotal, attributes)
from .test_attachments import _fake_clamd

REG = {"description": "échantillon suspect", "collected_at": "2026-11-20T10:00:00Z", "method": "copie depuis le poste",
       "sensitivity": "TLP:AMBER"}
OTHER_KEY = "Z" * 40

ALERT_SYSCHECK = {
    "timestamp": "2026-11-20T16:00:00.000+0000", "id": "1732118400.77",
    "rule": {"id": "554", "level": 7, "description": "File added to the system.", "groups": ["ossec", "syscheck"]},
    "agent": {"id": "003", "name": "srv-web-01"},
    "syscheck": {"path": "/tmp/x<script>.bin", "event": "added", "md5_after": "d" * 32, "sha1_after": EICAR_SHA1,
                 "sha256_after": EICAR_SHA256, "sha256_before": QUIET_SHA256, "size_after": "68"},
    "data": {"win": {"eventdata": {"hashes": f"SHA1={'A' * 40},MD5={'B' * 32},SHA256={HOSTILE_SHA256.upper()},IMPHASH={'C' * 32}"}},
             "virustotal": {"source": {"sha1": "1" * 40}}, "srcip": "185.220.101.4", "trop_long": "e" * 65,
             "liste": [{"sha256": "2" * 64}], "nombre": 12},
    "full_log": "hors des champs lus : " + "9" * 64,
}


def zip_bytes(name="suspect.bin", content=b"contenu") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, content)
    return buf.getvalue()


def png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (12, 12), (200, 30, 30)).save(buf, format="PNG")
    return buf.getvalue() + b"DONNEES-APRES-IEND"         # retirées par le ré-encodage : l'empreinte stockée diffère


def upload(c, data, name="suspect.zip"):
    r = c.post("/api/v1/tickets/ACME-1/attachments", data=REG, files={"file": (name, data, "application/octet-stream")})
    assert r.status_code == 201, r.text
    return r.json()


def fresh(db):
    db.rollback()
    db.expire_all()


def audit_rows(db, action):
    fresh(db)
    return db.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.seq)).all()


def set_key(c, key=API_KEY):
    r = c.put("/api/v1/me/virustotal", json={"api_key": key})
    assert r.status_code == 200, r.text
    return r


def lookup(c, ref="ACME-1", **body):
    return c.post(f"/api/v1/tickets/{ref}/virustotal", json=body)


def manual(c, digest, ref="ACME-1"):
    return lookup(c, ref, source="saisie", hash=digest)


@pytest.fixture
def fake():
    server = FakeVirusTotal().start()
    yield server
    server.stop()


@pytest.fixture
def vapp(settings, fake):
    """Application dont l'adresse de VirusTotal est remplacée par le faux serveur local (réglage d'essai)."""
    settings.virustotal_url, settings.virustotal_allow_loopback = fake.url, True
    settings.virustotal_user_limit = settings.virustotal_client_limit = 1000
    return create_app(settings)


@pytest.fixture
def ticket(vapp, db, world, alert):
    ingest(vapp, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    _accord(db)
    return "ACME-1"


def _accord(db, keys=("ACME", "DELTA"), valeur=True):
    """Accord des clients à la recherche VirusTotal (PDIS IV.1.g), refusée par défaut."""
    from sqlalchemy import update
    from keryx.models import Tenant
    db.execute(update(Tenant).where(Tenant.key.in_(keys)).values(virustotal_autorise=valeur))
    db.commit()


@pytest.fixture
def analyst(vapp, db, world, ticket):
    c = login(vapp, db, "analyst_acme")
    set_key(c)
    return c


# ---------------------------------------------------------------- la clé de l'utilisateur
def test_cle_chiffree_jamais_renvoyee_ni_journalisee_ni_auditee(vapp, db, world, ticket, fake, caplog):
    caplog.set_level(logging.DEBUG)
    a = login(vapp, db, "analyst_acme")
    assert a.get("/api/v1/me/virustotal").json() == {"configured": False, "enabled": True}
    r = set_key(a)
    assert r.json() == {"configured": True, "enabled": True} and API_KEY not in r.text
    assert a.get("/api/v1/me/virustotal").json() == {"configured": True, "enabled": True}
    # Au repos : chiffrée, liée au compte (recopiée sur un autre compte, elle ne se déchiffre pas)
    fresh(db)
    me, other = (db.scalars(select(User).where(User.username == n)).one() for n in ("analyst_acme", "manager"))
    assert me.vt_api_key.startswith("v1:") and API_KEY not in me.vt_api_key and other.vt_api_key is None
    assert vapp.state.box.decrypt(me.vt_api_key, f"vt_api_key:{me.id}") == API_KEY
    with pytest.raises(InvalidTag):
        vapp.state.box.decrypt(me.vt_api_key, f"vt_api_key:{other.id}")
    # Elle sert : la recherche part avec elle, en en-tête, vers le seul chemin attendu
    assert manual(a, EICAR_SHA256).status_code == 201
    sent = fake.requests[-1]
    assert sent["path"] == f"/api/v3/files/{EICAR_SHA256}" and sent["headers"]["x-apikey"] == API_KEY
    assert sent["headers"]["Accept-Encoding"] == "identity" and "Cookie" not in sent["headers"] and "Authorization" not in sent["headers"]
    # … et n'apparaît nulle part ailleurs : réponses, fiche, /me, comptes vus par l'Admin, audit, journaux
    adm = login(vapp, db, "admin")
    seen = [a.get(p).text for p in ("/api/v1/me", "/api/v1/me/virustotal", "/api/v1/tickets/ACME-1", "/api/v1/tickets/ACME-1/virustotal/hashes")]
    seen += [adm.get(p).text for p in ("/api/v1/admin/users", "/api/v1/admin/revue-comptes", "/api/v1/audit/entries")]
    assert not any(API_KEY in text for text in seen)
    assert "vt_api_key" not in adm.get("/api/v1/admin/users").text and "virustotal" not in adm.get("/api/v1/admin/users").text.lower()
    fresh(db)
    assert API_KEY not in json.dumps([[e.actor, e.action, e.object_id, e.details] for e in db.scalars(select(AuditEntry))])
    assert [e.details for e in audit_rows(db, "auth.vt_key_set")] == [{"remplacement": False}]
    assert API_KEY not in caplog.text
    # Remplacement, puis retrait
    assert set_key(a, OTHER_KEY).status_code == 200
    assert audit_rows(db, "auth.vt_key_set")[-1].details == {"remplacement": True}
    fresh(db)
    assert vapp.state.box.decrypt(db.scalars(select(User).where(User.username == "analyst_acme")).one().vt_api_key, f"vt_api_key:{me.id}") == OTHER_KEY
    assert a.delete("/api/v1/me/virustotal").json() == {"configured": False, "enabled": True}
    fresh(db)
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().vt_api_key is None
    assert len(audit_rows(db, "auth.vt_key_removed")) == 1
    assert a.delete("/api/v1/me/virustotal").status_code == 200 and len(audit_rows(db, "auth.vt_key_removed")) == 1   # rien à retirer : rien à tracer
    r = manual(a, EICAR_SHA256)
    assert r.status_code == 409 and "profil" in r.json()["detail"]


@pytest.mark.parametrize("key", ["", "courte", "a" * 31, "a" * 129, "a" * 300, "clé-avec-accent-" + "a" * 30, "a" * 40 + " b",
                                 "a" * 20 + "\n" + "a" * 20, "<script>" + "a" * 40, "a" * 32 + "-_", None, 12345, ["a" * 40]])
def test_cle_de_forme_invalide_refusee_sans_etre_recopiee(vapp, db, world, key):
    a = login(vapp, db, "analyst_acme")
    r = a.put("/api/v1/me/virustotal", json={"api_key": key})
    assert r.status_code == 422, (key, r.text)
    if isinstance(key, str) and len(key) > 8:
        assert key not in r.text and key[:16] not in r.text
    assert a.get("/api/v1/me/virustotal").json()["configured"] is False
    assert a.put("/api/v1/me/virustotal", json={"api_key": API_KEY, "url": "https://ailleurs.example"}).status_code == 422   # rien d'autre n'est réglable


def test_cle_collee_avec_des_blancs_autour(vapp, db, world, ticket, fake):
    """Une clé collée avec un retour à la ligne ou des espaces autour est enregistrée sans eux."""
    a = login(vapp, db, "analyst_acme")
    set_key(a, f"  {API_KEY}\n")
    assert manual(a, EICAR_SHA256).status_code == 201 and fake.requests[-1]["headers"]["x-apikey"] == API_KEY


def test_cle_reservee_a_l_analyste_et_au_manager(vapp, db, world, fake):
    for who in ("client_acme", "admin"):
        c = login(vapp, db, who)
        assert c.get("/api/v1/me/virustotal").status_code == 403, who
        assert c.put("/api/v1/me/virustotal", json={"api_key": API_KEY}).status_code == 403, who
        assert c.put("/api/v1/me/virustotal", json={"api_key": 5}).status_code == 403, who      # le rôle avant le schéma
        assert c.delete("/api/v1/me/virustotal").status_code == 403, who
        assert c.get("/api/v1/me").json()["features"]["virustotal"] is False, who
    assert set_key(login(vapp, db, "manager")).status_code == 200
    assert login(vapp, db, "manager").get("/api/v1/me").json()["features"]["virustotal"] is True
    assert TestClient(vapp).get("/api/v1/me/virustotal").status_code == 401
    assert fake.requests == []                                   # enregistrer une clé n'appelle jamais VirusTotal


def test_cle_effacee_quand_le_compte_quitte_l_equipe(vapp, db, world):
    set_key(login(vapp, db, "analyst_acme"))
    adm = login(vapp, db, "admin")
    assert adm.patch("/api/v1/admin/users/analyst_acme", json={"display_name": "Analyste"}).status_code == 200
    fresh(db)
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().vt_api_key is not None   # rôle inchangé : clé gardée
    assert adm.patch("/api/v1/admin/users/analyst_acme", json={"role": "client"}).status_code == 200
    fresh(db)
    assert db.scalars(select(User).where(User.username == "analyst_acme")).one().vt_api_key is None
    assert audit_rows(db, "user.update")[-1].details["cle_virustotal"] == "effacee"


def test_cle_illisible_apres_changement_de_cle_maitresse(vapp, db, world, ticket, analyst, fake):
    fresh(db)
    me = db.scalars(select(User).where(User.username == "analyst_acme")).one()
    me.vt_api_key = "v1:" + "A" * 80
    db.commit()
    r = manual(analyst, EICAR_SHA256)
    assert r.status_code == 409 and "plus lisible" in r.json()["detail"] and fake.requests == []


# ---------------------------------------------------------------- rôles et cloisonnement
def test_roles_et_cloisonnement(vapp, db, world, ticket, analyst, fake):
    assert manual(analyst, EICAR_SHA256).status_code == 201
    seen = len(fake.requests)
    client = login(vapp, db, "client_acme")
    assert manual(client, EICAR_SHA256).status_code == 403
    assert lookup(client, source="tout", hash=5).status_code == 403                 # le rôle avant le schéma
    assert client.get("/api/v1/tickets/ACME-1/virustotal/hashes").status_code == 403
    adm = login(vapp, db, "admin")
    assert manual(adm, EICAR_SHA256).status_code == 403 and lookup(adm).status_code == 403
    assert adm.get("/api/v1/tickets/ACME-1/virustotal/hashes").status_code == 403
    assert audit_rows(db, "ticket.access_denied")[-1].details == {"role": "admin", "objet": "virustotal"}
    # l'Admin voit dans l'audit qu'une recherche a eu lieu, jamais sur quelle empreinte ni avec quel résultat
    seen_by_admin = adm.get("/api/v1/audit/entries", params={"action": "ticket.virustotal"})
    assert [e["details"] for e in seen_by_admin.json()["items"]] == [{"masque": True}] and EICAR_SHA256 not in seen_by_admin.text
    other = login(vapp, db, "analyst_delta")                     # analyste sans accès à ce client
    set_key(other)
    assert manual(other, EICAR_SHA256).status_code == 404
    assert other.get("/api/v1/tickets/ACME-1/virustotal/hashes").status_code == 404
    assert TestClient(vapp).post("/api/v1/tickets/ACME-1/virustotal", json={"source": "saisie", "hash": EICAR_SHA256}).status_code == 401
    assert len(fake.requests) == seen                            # aucun de ces refus n'a atteint VirusTotal
    fresh(db)
    assert len(db.scalars(select(HashLookup)).all()) == 1
    # Le manager affecté au client voit la recherche de l'analyste ; l'analyste d'un autre client, jamais
    m = login(vapp, db, "manager").get("/api/v1/tickets/ACME-1").json()
    assert [x["hash"] for x in m["virustotal"]["lookups"]] == [EICAR_SHA256] and m["virustotal"]["lookups"][0]["actor"] == "analyst_acme"


def test_vue_client_sans_aucune_trace_des_recherches(vapp, db, world, ticket, analyst):
    cl = login(vapp, db, "client_acme")
    piece = cl.post("/api/v1/tickets/ACME-1/attachments", data=REG, files={"file": ("depot.zip", zip_bytes(), "application/zip")}).json()
    assert lookup(analyst, source="piece", attachment_id=piece["id"]).status_code == 201     # pièce visible du client
    assert manual(analyst, EICAR_SHA256).status_code == 201
    team = analyst.get("/api/v1/tickets/ACME-1")
    assert len(team.json()["virustotal"]["lookups"]) == 2 and "virustotal_lookup" in team.text
    r = cl.get("/api/v1/tickets/ACME-1")
    assert r.status_code == 200 and "virustotal" not in r.json()
    low = r.text.lower()
    assert "virustotal" not in low and EICAR_SHA256 not in low and "trojan" not in low and "eicar" not in low
    assert "virustotal" not in cl.get("/api/v1/tickets").text.lower()
    fresh(db)
    events = db.scalars(select(TicketEvent).where(TicketEvent.action == "virustotal_lookup")).all()
    assert len(events) == 2 and not any(e.visible_client for e in events)
    assert cl.get(f"/api/v1/attachments/{piece['id']}/custody").status_code == 403          # la chaîne de possession reste à l'équipe


# ---------------------------------------------------------------- sources d'empreinte
def test_empreinte_d_une_piece_prise_par_le_serveur(vapp, db, world, ticket, analyst, fake):
    data = zip_bytes()
    digest = hashlib.sha256(data).hexdigest()
    fake.files[digest] = attributes(digest, malicious=9, name="suspect.bin")
    piece = upload(analyst, data)
    # le navigateur ne choisit pas l'empreinte d'une pièce
    r = lookup(analyst, source="piece", attachment_id=piece["id"], hash=EICAR_SHA256)
    assert r.status_code == 422 and "prise par le serveur" in r.json()["detail"] and fake.requests == []
    assert lookup(analyst, source="piece").status_code == 422
    assert lookup(analyst, source="piece", attachment_id="pas-un-identifiant").status_code == 422
    assert lookup(analyst, source="piece", attachment_id="01a2002b-ff98-72b1-b221-3b55cda07ffc").status_code == 404
    r = lookup(analyst, source="piece", attachment_id=piece["id"])
    assert r.status_code == 201, r.text
    out = r.json()
    assert fake.requests[-1]["path"] == f"/api/v3/files/{digest}" and len(fake.requests) == 1
    assert out["hash"] == digest and out["source_type"] == "piece" and out["source_id"] == piece["id"] and out["origin"] == "piece"
    assert out["status"] == "trouve" and out["summary"]["stats"]["malicious"] == 9
    # chaîne de possession de la pièce, registre des actions (interne), audit
    custody = analyst.get(f"/api/v1/attachments/{piece['id']}/custody").json()["items"]
    assert [(c["actor"], c["action"]) for c in custody] == [("analyst_acme", "depot"), ("analyst_acme", "analyse_virustotal")]
    assert digest in custody[1]["reason"] and "fichier connu de VirusTotal" in custody[1]["reason"] and custody[1]["ts"].endswith("Z")
    row = audit_rows(db, "ticket.virustotal_lookup")[-1]
    assert row.actor == "analyst_acme" and row.object_id == "ACME-1" and row.tenant_id == world["tenants"]["ACME"].id
    assert row.details == {"empreinte": digest, "type": "sha256", "source": "piece", "piece": piece["id"], "statut": "trouve",
                           "malveillant": 9, "suspect": 1, "inoffensif": 0, "non_detecte": 61}
    # une pièce d'un autre ticket n'est pas atteignable par celui-ci
    ingest(vapp, world["keys"]["DELTA"], ALERT_SSH_BRUTEFORCE)
    m = login(vapp, db, "manager")
    set_key(m)
    assert lookup(m, "DELTA-1", source="piece", attachment_id=piece["id"]).status_code == 404
    assert len(fake.requests) == 1


def test_image_reencodee_l_empreinte_du_fichier_recu_est_cherchee(vapp, db, world, ticket, analyst, fake):
    """Keryx ré-encode les images : l'empreinte de la pièce est celle d'un fichier qui n'existe que dans Keryx. C'est
    l'empreinte du fichier reçu (motif de l'événement de dépôt) qui est cherchée, quand elle est connue."""
    data = png_bytes()
    received = hashlib.sha256(data).hexdigest()
    piece = upload(analyst, data, "capture.png")
    assert piece["kind"] == "image" and piece["sha256"] != received
    listed = analyst.get("/api/v1/tickets/ACME-1/virustotal/hashes").json()["pieces"]
    assert listed == [{"source": "piece", "attachment_id": piece["id"], "filename": "capture.png", "hash": received,
                       "hash_type": "sha256", "origin": "recue", "quarantine": False}]
    r = lookup(analyst, source="piece", attachment_id=piece["id"])
    assert r.status_code == 201 and r.json()["hash"] == received and r.json()["origin"] == "recue" and r.json()["status"] == "inconnu"
    assert fake.requests[-1]["path"] == f"/api/v3/files/{received}"
    fresh(db)
    last = db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == piece["id"]).order_by(CustodyEvent.ts)).all()[-1]
    assert last.action == "analyse_virustotal" and received in last.reason and "avant ré-encodage" in last.reason and "inconnu" in last.reason
    # sans empreinte d'origine connue (dépôt ancien) : celle de la pièce, annoncée comme telle
    first = db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == piece["id"], CustodyEvent.action == "depot")).one()
    first.reason = ""
    db.commit()
    r = lookup(analyst, source="piece", attachment_id=piece["id"])
    assert r.json()["hash"] == piece["sha256"] and r.json()["origin"] == "piece"


def test_piece_en_quarantaine_et_preuve_externe(settings, db, world, alert, fake):
    _accord(db)
    """Une pièce en quarantaine garde l'empreinte de l'ORIGINAL (c'est l'archive chiffrée qui est stockée) : c'est le
    cas le plus utile. Une preuve externe : l'empreinte déclarée."""
    clamd = _fake_clamd(b"stream: Eicar-Test-Signature FOUND\0")
    settings.clamav_host, settings.clamav_port = "127.0.0.1", clamd.getsockname()[1]
    settings.virustotal_url, settings.virustotal_allow_loopback = fake.url, True
    app = create_app(settings)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    set_key(a)
    original = zip_bytes("eicar.com", EICAR)
    digest = hashlib.sha256(original).hexdigest()
    fake.files[digest] = attributes(digest, malicious=40, name="eicar.zip")
    piece = upload(a, original)
    assert piece["scan_status"] == "quarantaine" and piece["sha256"] == digest
    r = lookup(a, source="piece", attachment_id=piece["id"])
    assert r.status_code == 201 and r.json()["hash"] == digest and r.json()["summary"]["stats"]["malicious"] == 40
    ext = a.post("/api/v1/tickets/ACME-1/preuves-externes", json={
        "description": "image disque", "collected_at": "2026-11-20T10:00:00Z", "method": "copie bit à bit",
        "sha256": EICAR_SHA256, "location": "coffre 3", "filename": "disque.dd"}).json()
    r = lookup(a, source="piece", attachment_id=ext["id"])
    assert r.status_code == 201 and r.json()["source_type"] == "preuve_externe" and r.json()["origin"] == "declaree"
    assert r.json()["hash"] == EICAR_SHA256 and fake.requests[-1]["path"].endswith(EICAR_SHA256)
    listed = a.get("/api/v1/tickets/ACME-1/virustotal/hashes").json()["pieces"]
    assert [(p["source"], p["origin"], p["quarantine"]) for p in listed] == [("piece", "piece", True), ("preuve_externe", "declaree", False)]
    custody = a.get(f"/api/v1/attachments/{ext['id']}/custody").json()["items"]
    assert [c["action"] for c in custody] == ["declaration", "analyse_virustotal"] and "empreinte déclarée" in custody[1]["reason"]
    assert not any(req["method"] != "GET" for req in fake.requests)          # jamais un envoi de fichier
    clamd.close()


def test_extraction_des_empreintes_d_une_alerte():
    found = vt.extract_alert_hashes(ALERT_SYSCHECK)
    assert [(c["hash"], c["hash_type"], c["field"]) for c in found] == [
        (EICAR_SHA1, "sha1", "syscheck.sha1_after"), (EICAR_SHA256, "sha256", "syscheck.sha256_after"),
        (QUIET_SHA256, "sha256", "syscheck.sha256_before"),
        ("a" * 40, "sha1", "data.win.eventdata.hashes"), (HOSTILE_SHA256, "sha256", "data.win.eventdata.hashes"),
        ("1" * 40, "sha1", "data.virustotal.source.sha1"), ("2" * 64, "sha256", "data.liste.sha256")]
    assert all(c["file"] == "/tmp/x<script>.bin" for c in found[:3]) and all(c["file"] == "" for c in found[3:])
    hashes = {c["hash"] for c in found}
    # ni MD5, ni IMPHASH, ni suite de 65 caractères, ni texte hors de syscheck et data
    assert "d" * 32 not in hashes and not any(len(h) not in (40, 64) for h in hashes) and "9" * 64 not in hashes
    # défensif : jamais d'exception, quelle que soit la forme ; bornes de profondeur et de nombre
    for junk in (None, [], "texte", 5, {"syscheck": "x", "data": None}, {"data": [1, 2]}, {"syscheck": {"sha256_after": 5}}):
        assert vt.extract_alert_hashes(junk) == []
    deep = {}
    cur = deep
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    cur["sha256"] = "3" * 64
    assert vt.extract_alert_hashes({"data": deep}) == []
    many = {"data": {f"k{i}": f"{i:064x}" for i in range(500)}}
    assert len(vt.extract_alert_hashes(many)) == vt.MAX_CANDIDATES
    assert vt.extract_alert_hashes({"data": {"x": "4" * 64 + " " + "z" * 5000}}) == []      # texte trop long : ignoré
    assert vt.extract_alert_hashes({"data": {"clé<b>\n": "5" * 64}})[0]["field"] == "data.cl__b__"


def test_empreintes_des_alertes_du_ticket(vapp, db, world, analyst, fake, alert):
    ingest(vapp, world["keys"]["ACME"], alert(ALERT_SYSCHECK))
    out = analyst.get("/api/v1/tickets/ACME-2/virustotal/hashes").json()
    assert out["configured"] is True and out["pieces"] == []
    assert [c["hash"] for c in out["alerts"]][:3] == [EICAR_SHA1, EICAR_SHA256, QUIET_SHA256] and len(out["alerts"]) == 7
    first = out["alerts"][0]
    assert first["source"] == "alerte" and first["field"] == "syscheck.sha1_after" and first["wazuh_id"] == "1732118400.77"
    assert first["file"] == "/tmp/x<script>.bin" and first["received_at"].endswith("Z")
    assert analyst.get("/api/v1/tickets/ACME-1/virustotal/hashes").json()["alerts"] == []     # l'alerte SSH n'en porte aucune
    assert audit_rows(db, "ticket.virustotal_hashes")[0].details == {"pieces": 0, "alertes": 7}
    assert fake.requests == []                                    # lister ne fait rien sortir
    # recherche d'une empreinte d'alerte : SHA-1 accepté, rattachée à l'alerte brute
    r = lookup(analyst, "ACME-2", source="alerte", hash=EICAR_SHA1)
    assert r.status_code == 201, r.text
    assert r.json()["hash_type"] == "sha1" and r.json()["source_type"] == "alerte" and r.json()["source_id"] == first["alert"]
    assert r.json()["summary"]["sha256"] == EICAR_SHA256 and r.json()["url"] == f"https://www.virustotal.com/gui/file/{EICAR_SHA1}"
    # une empreinte que les alertes du ticket ne contiennent pas n'est pas une « empreinte d'alerte »
    r = lookup(analyst, "ACME-2", source="alerte", hash=UNKNOWN_SHA256)
    assert r.status_code == 422 and "aucune alerte brute" in r.json()["detail"]
    assert lookup(analyst, "ACME-1", source="alerte", hash=EICAR_SHA1).status_code == 422       # ni celles d'un autre ticket
    assert len(fake.requests) == 1


@pytest.mark.parametrize("body", [
    {"source": "saisie", "hash": "d" * 32},                         # MD5 : refusé
    {"source": "saisie", "hash": "a" * 63}, {"source": "saisie", "hash": "a" * 65}, {"source": "saisie", "hash": "a" * 41},
    {"source": "saisie", "hash": "A" * 64},                         # majuscules : forme stricte
    {"source": "saisie", "hash": "g" * 64}, {"source": "saisie", "hash": " " + "a" * 64}, {"source": "saisie", "hash": "a" * 64 + "\n"},
    {"source": "saisie", "hash": "a" * 40 + "/../../x"}, {"source": "saisie", "hash": f"{EICAR_SHA256}?x=1"},
    {"source": "saisie", "hash": ""}, {"source": "saisie"}, {"source": "saisie", "hash": None}, {"source": "saisie", "hash": 5},
    {"source": "saisie", "hash": ["a" * 64]}, {"hash": "a" * 64}, {}, {"source": "fichier", "hash": "a" * 64},
    {"source": "saisie", "hash": "a" * 64, "url": "https://ailleurs.example"},
    {"source": "saisie", "hash": "a" * 64, "attachment_id": "01a2002b-ff98-72b1-b221-3b55cda07ffc"},
    {"source": "alerte"}, {"source": "alerte", "hash": "A" * 40},
])
def test_empreinte_invalide_422_rien_ne_sort(vapp, db, world, ticket, analyst, fake, body):
    r = lookup(analyst, **body)
    assert r.status_code == 422, (body, r.text)
    assert fake.requests == []
    fresh(db)
    assert db.scalars(select(HashLookup)).all() == []


# ---------------------------------------------------------------- résultats
def test_fichier_connu_resume_borne_et_lien_construit_par_keryx(vapp, db, world, ticket, analyst, fake):
    r = manual(analyst, EICAR_SHA256)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["status"] == "trouve" and out["hash"] == EICAR_SHA256 and out["hash_type"] == "sha256"
    assert out["source_type"] == "saisie" and out["source_id"] is None and out["actor"] == "analyst_acme"
    assert out["created_at"].endswith("Z")
    s = out["summary"]
    assert s["stats"] == {"malicious": 62, "suspicious": 1, "harmless": 0, "undetected": 8, "total": 73}
    assert s["last_analysis_date"] == "2026-11-14T10:00:00.000Z" and s["first_submission_date"] == "2006-05-22T12:42:02.000Z"
    assert s["name"] == "eicar.com" and s["type"] == "Win32 EXE" and s["size"] == 68 and s["threat_label"] == "trojan.eicar/test"
    assert s["sha256"] == EICAR_SHA256
    assert len(s["engine_names"]) == vt.MAX_ENGINE_NAMES and s["engine_names"][0] == {"engine": "Moteur00", "result": "Trojan.Generic.0"}
    # le lien vient de Keryx : hôte officiel + empreinte ; rien de la réponse (« links ») n'est repris
    assert out["url"] == f"https://www.virustotal.com/gui/file/{EICAR_SHA256}" and "attaquant.example" not in r.text
    # enregistré, affiché sur la fiche de l'équipe, inscrit au registre des actions
    fresh(db)
    row = db.scalars(select(HashLookup)).one()
    assert (row.hash, row.hash_type, row.source_type, row.status, row.actor) == (EICAR_SHA256, "sha256", "saisie", "trouve", "analyst_acme")
    assert row.tenant_id == world["tenants"]["ACME"].id and row.summary == s and len(json.dumps(row.summary)) < 4000
    t = analyst.get("/api/v1/tickets/ACME-1").json()
    assert t["virustotal"]["lookups"] == [{k: v for k, v in out.items() if k != "origin"}]
    event = [e for e in t["events"] if e["action"] == "virustotal_lookup"][0]
    assert event["details"]["empreinte"] == EICAR_SHA256 and event["details"]["malveillant"] == 62 and event["ts"].endswith("Z")
    # réponse compressée malgré la demande : acceptée, même borne
    fake.mode = "gzip"
    assert manual(analyst, EICAR_SHA256).json()["summary"] == s


def test_inconnu_de_virustotal_jamais_presente_comme_sain(vapp, db, world, ticket, analyst, fake):
    r = manual(analyst, UNKNOWN_SHA256)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["status"] == "inconnu" and out["summary"] == {} and out["url"].endswith(UNKNOWN_SHA256)
    low = r.text.lower()
    assert "sain" not in low and "clean" not in low and "harmless" not in low and "inoffensif" not in low
    row = audit_rows(db, "ticket.virustotal_lookup")[-1]
    assert row.details == {"empreinte": UNKNOWN_SHA256, "type": "sha256", "source": "saisie", "statut": "inconnu"}
    fresh(db)
    assert db.scalars(select(HashLookup)).one().status == "inconnu"
    # un fichier connu sans aucune détection n'est pas « sain » non plus : seuls des compteurs sont rendus
    quiet = manual(analyst, QUIET_SHA256).json()
    assert quiet["status"] == "trouve" and quiet["summary"]["stats"]["malicious"] == 0 and quiet["summary"]["engine_names"] == []
    assert "sain" not in json.dumps(quiet).lower() and "clean" not in json.dumps(quiet).lower()
    # une page 404 qui ne vient pas de l'API (mandataire, mauvaise adresse) n'est PAS un « inconnu »
    fake.mode = "html404"
    r = manual(analyst, UNKNOWN_SHA256)
    assert r.status_code == 502 and audit_rows(db, "ticket.virustotal_lookup_failed")[-1].details["erreur"] == "reponse_invalide"
    fresh(db)
    assert len(db.scalars(select(HashLookup)).all()) == 2


def test_texte_hostile_assaini(vapp, db, world, ticket, analyst):
    r = manual(analyst, HOSTILE_SHA256)
    assert r.status_code == 201, r.text
    s = r.json()["summary"]
    # texte pur et borné : le balisage reste du texte, plus de caractère de contrôle ni de marque de sens d'écriture
    assert s["name"].startswith("facture<script>alert(1)</script>\\x1b[31m\\x00") and "\u202e" not in s["name"]
    assert s["type"] == "<b>PE</b>\\x07" and len(s["threat_label"]) == 100 and "\u202e" not in s["threat_label"]
    hostile = [e for e in s["engine_names"] if "script" in e["engine"]][0]
    assert hostile == {"engine": "<script>x</script>", "result": "Evil\\x0d\\x0a�<svg onload=1>"}
    text = json.dumps(s, ensure_ascii=False)
    assert not any(c in text for c in ("\x1b", "\x00", "\x07", "\r", "\u202e"))
    # types inattendus : compteur à 0, date absente ; jamais d'exception ni de valeur recopiée telle quelle
    assert s["stats"]["malicious"] == 0 and s["last_analysis_date"] is None
    assert all(isinstance(v, int) for v in s["stats"].values())
    # l'audit et le registre des actions ne portent que l'empreinte, le statut et les compteurs
    row = audit_rows(db, "ticket.virustotal_lookup")[-1]
    assert "script" not in json.dumps(row.details) and set(row.details) == {"empreinte", "type", "source", "statut", "malveillant",
                                                                             "suspect", "inoffensif", "non_detecte"}


def test_resume_face_a_des_formes_inattendues():
    for junk in ({}, {"last_analysis_stats": "x", "last_analysis_results": [1], "popular_threat_classification": 3},
                 {"last_analysis_stats": {"malicious": -5, "suspicious": True, "harmless": 10**9, "undetected": 1.5}},
                 {"meaningful_name": {"a": 1}, "size": "grand", "sha256": "pas une empreinte", "first_submission_date": -1},
                 {"last_analysis_results": {"m": "x", "n": {"category": "malicious", "result": None}, 5: {}}}):
        s = vt.summarize(junk)
        assert s["stats"]["malicious"] == 0 and s["stats"]["harmless"] == 0 and s["engine_names"] == []
        assert s["name"] == "" and s["size"] is None and s["sha256"] is None and s["first_submission_date"] is None


def test_erreurs_de_virustotal_messages_propres_rien_d_enregistre(vapp, db, world, ticket, analyst, fake, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    def failing(status, reason, words):
        r = manual(analyst, EICAR_SHA256)
        assert r.status_code == status, (reason, r.text)
        assert r.headers["content-type"].startswith("application/problem+json")
        assert words in r.json()["detail"], r.json()["detail"]
        assert API_KEY not in r.text and "DETAIL-INTERNE" not in r.text
        assert audit_rows(db, "ticket.virustotal_lookup_failed")[-1].details == {
            "empreinte": EICAR_SHA256, "type": "sha256", "source": "saisie", "erreur": reason}

    fake.mode = "401"
    failing(502, "cle_refusee", "dans votre profil")
    fake.mode = "403"
    failing(502, "cle_refusee", "refuse votre clé")
    fake.mode = "429"
    failing(429, "quota", "quota")
    fake.mode = "500"
    failing(502, "statut_500", "erreur (500)")
    fake.mode = "junk"
    failing(502, "reponse_invalide", "n'est pas celle de son API")
    fake.mode = "bad_shape"
    failing(502, "reponse_invalide", "n'est pas celle de son API")
    fake.mode = "huge"
    failing(502, "reponse_trop_grande", "taille admise")
    fake.mode = "gzip_bomb"
    failing(502, "reponse_trop_grande", "taille admise")
    fake.mode = "other_file"
    r = manual(analyst, QUIET_SHA256)
    assert r.status_code == 502 and "autre fichier" in r.json()["detail"]
    # redirection : jamais suivie (la cible ne reçoit rien, surtout pas la clé)
    fake.mode = "redirect"
    before = len(fake.requests)
    failing(502, "redirection", "redirection")
    assert len(fake.requests) == before + 1
    # trop lent : délai court
    fake.mode = "ok"
    monkeypatch.setattr(vt, "READ_TIMEOUT_S", 0.4)
    fake.delay = 1.2
    failing(503, "delai", "délai")
    fake.delay = 0
    assert manual(analyst, EICAR_SHA256).status_code == 201       # rétabli : la recherche aboutit de nouveau
    # arrêté : injoignable
    fake.stop()
    failing(503, "injoignable", "injoignable")
    # un échec n'enregistre aucun résultat : ni registre, ni événement du ticket ; seulement l'audit
    fresh(db)
    assert len(db.scalars(select(HashLookup)).all()) == 1
    assert len(db.scalars(select(TicketEvent).where(TicketEvent.action == "virustotal_lookup")).all()) == 1
    assert API_KEY not in caplog.text
    fresh(db)
    assert API_KEY not in json.dumps([e.details for e in db.scalars(select(AuditEntry))])


def test_recherche_possible_sur_un_ticket_clos(vapp, db, world, ticket, analyst):
    """Comme un téléchargement : la recherche ne modifie pas la pièce, elle s'ajoute à sa chaîne de possession."""
    piece = upload(analyst, zip_bytes())
    fresh(db)
    t = db.scalars(select(Ticket).where(Ticket.ref == "ACME-1")).one()
    t.status, t.verdict = "faux_positif", "faux_positif"
    db.commit()
    assert analyst.post("/api/v1/tickets/ACME-1/comments", json={"body_html": "<p>x</p>"}).status_code == 409   # bien clos
    assert lookup(analyst, source="piece", attachment_id=piece["id"]).status_code == 201
    assert manual(analyst, EICAR_SHA256).status_code == 201


def test_echec_sur_une_piece_sans_evenement_de_possession(vapp, db, world, ticket, analyst, fake):
    piece = upload(analyst, zip_bytes())
    fake.mode = "500"
    assert lookup(analyst, source="piece", attachment_id=piece["id"]).status_code == 502
    fresh(db)
    assert [c.action for c in db.scalars(select(CustodyEvent).where(CustodyEvent.attachment_id == piece["id"]))] == ["depot"]
    assert audit_rows(db, "ticket.virustotal_lookup_failed")[-1].details["piece"] == piece["id"]


def test_limite_de_debit_par_utilisateur_et_par_client(settings, db, world, alert, fake):
    _accord(db)
    settings.virustotal_url, settings.virustotal_allow_loopback = fake.url, True
    assert settings.virustotal_user_limit == 4                    # défaut : 4 par minute et par utilisateur
    settings.virustotal_client_limit = 5
    app = create_app(settings)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    set_key(a)
    assert manual(a, "a" * 64 + "x").status_code == 422           # une demande refusée ne consomme rien
    assert [manual(a, EICAR_SHA256).status_code for _ in range(5)] == [201, 201, 201, 201, 429]
    assert len(fake.requests) == 4                                # la cinquième n'a pas atteint VirusTotal
    m = login(app, db, "manager")                                 # un autre utilisateur, le même client : limite du client
    set_key(m)
    r = [manual(m, EICAR_SHA256) for _ in range(2)]
    assert [x.status_code for x in r] == [201, 429] and "Trop de recherches" in r[1].json()["detail"]
    assert len(fake.requests) == 5


# ---------------------------------------------------------------- interrupteur d'instance, adresse, mandataire
def test_interrupteur_d_instance_coupe(settings, db, world, alert, fake, monkeypatch):
    _accord(db)
    settings.virustotal_url, settings.virustotal_allow_loopback = fake.url, True
    app = create_app(settings)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    set_key(a)
    assert manual(a, EICAR_SHA256).status_code == 201
    seen = len(fake.requests)
    monkeypatch.setenv("KERYX_VIRUSTOTAL_ENABLED", "false")
    assert Settings().virustotal_enabled is False
    monkeypatch.delenv("KERYX_VIRUSTOTAL_ENABLED")
    assert Settings().virustotal_enabled is True                  # disponible par défaut
    settings.virustotal_enabled = False
    off = create_app(settings)
    a = login(off, db, "analyst_acme")
    for r in (manual(a, EICAR_SHA256), lookup(a, source="x"), a.get("/api/v1/tickets/ACME-1/virustotal/hashes"),
              a.put("/api/v1/me/virustotal", json={"api_key": API_KEY}), a.put("/api/v1/me/virustotal", json={})):
        assert r.status_code == 409 and "désactivée" in r.json()["detail"], r.text
    # rien dans l'interface : indicateur à faux, fiche sans bloc « virustotal »
    assert a.get("/api/v1/me").json()["features"]["virustotal"] is False
    assert "virustotal" not in a.get("/api/v1/tickets/ACME-1").json()
    assert a.get("/api/v1/me/virustotal").json() == {"configured": True, "enabled": False}
    assert a.delete("/api/v1/me/virustotal").json() == {"configured": False, "enabled": False}   # un secret s'efface toujours
    assert manual(login(off, db, "client_acme"), EICAR_SHA256).status_code == 403                # les rôles d'abord
    assert len(fake.requests) == seen
    # coupée, la fonction ne contrôle même pas son adresse : une instance sans VirusTotal démarre toujours
    settings.virustotal_url = "ftp://n-importe-quoi"
    assert TestClient(create_app(settings)).get("/healthz").status_code == 200


def test_adresse_de_base_hote_fixe_et_reglage_d_essai(settings):
    assert vt.parse_base_url(None) == vt.parse_base_url("") == "https://www.virustotal.com"
    assert vt.parse_base_url("https://vt-essai.example:8443/") == "https://vt-essai.example:8443"
    assert vt.parse_base_url("http://127.0.0.1:9000", allow_loopback=True) == "http://127.0.0.1:9000"
    assert vt.parse_base_url("http://localhost:9000", allow_loopback=True) == "http://localhost:9000"
    assert vt.parse_base_url("http://[::1]:9000", allow_loopback=True) == "http://[::1]:9000"
    for url, loop in (("http://127.0.0.1:9000", False), ("http://vt-essai.example", True), ("http://10.0.0.5:9000", True),
                      ("http://169.254.169.254", True), ("ftp://127.0.0.1", True), ("https://moi:secret@vt.example", False),
                      ("https://vt.example/api", False), ("https://vt.example/?x=1", False), ("https://vt.example/#f", False),
                      ("https://vt exemple", False), ("https://", False), ("https://vt.example:99999", False),
                      ("https://nom_invalide.example", False), ("javascript:alert(1)", True)):
        with pytest.raises(vt.ConfigError) as exc:
            vt.parse_base_url(url, allow_loopback=loop)
        assert "secret" not in str(exc.value), url
    assert vt.parse_proxy(None) is None and vt.parse_proxy("http://mandataire.interne:3128") == "http://mandataire.interne:3128"
    for bad in ("socks5://m:1080", "http://u:p@m:3128", "http://m:3128/chemin", "mandataire:3128"):
        with pytest.raises(vt.ConfigError):
            vt.parse_proxy(bad)
    # une adresse refusée arrête le démarrage plutôt que la première recherche
    settings.virustotal_url = "http://127.0.0.1:9000"              # boucle locale en clair, sans la dérogation
    with pytest.raises(RuntimeError) as exc:
        create_app(settings)
    assert "KERYX_VIRUSTOTAL_URL" in str(exc.value)
    assert vt.gui_url(EICAR_SHA1) == f"https://www.virustotal.com/gui/file/{EICAR_SHA1}"
    for bad in ("d" * 32, "A" * 64, "a" * 64 + "/..", ""):
        with pytest.raises(ValueError):
            vt.gui_url(bad)
        with pytest.raises(ValueError):
            vt.Client().file_report(bad, API_KEY)                  # le client lui-même n'émet rien pour autre chose qu'une empreinte


def test_https_certificat_non_reconnu_refuse_la_cle_ne_part_pas(settings, db, world, alert, tmp_path, monkeypatch):
    _accord(db)
    """En HTTPS, le certificat est vérifié contre les autorités du système et rien ne permet de s'en passer : devant
    un serveur dont l'autorité est inconnue, la négociation échoue avant toute requête (la clé n'est pas envoyée)."""
    import ssl
    d = tmp_path / "pki"
    d.mkdir()
    server = FakeVirusTotal(tls_dir=d).start()
    try:
        settings.virustotal_url = server.url                      # HTTPS : accepté sans la dérogation de boucle locale
        app = create_app(settings)
        ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
        a = login(app, db, "analyst_acme")
        set_key(a)
        r = manual(a, EICAR_SHA256)
        assert r.status_code == 502 and "certificat TLS" in r.json()["detail"]
        assert server.requests == []
        assert audit_rows(db, "ticket.virustotal_lookup_failed")[-1].details["erreur"] == "certificat_refuse"
        # avec l'autorité du faux serveur reconnue (ici en remplaçant le magasin du système) : la voie HTTPS aboutit
        monkeypatch.setattr(vt, "_tls_context", lambda: ssl.create_default_context(cadata=server.ca_pem))
        r = manual(a, EICAR_SHA256)
        assert r.status_code == 201 and r.json()["summary"]["stats"]["malicious"] == 62
        assert server.requests[-1]["headers"]["x-apikey"] == API_KEY
    finally:
        server.stop()


def test_aucun_mandataire_d_environnement_mandataire_explicite_possible(settings, db, world, alert, fake, monkeypatch):
    _accord(db)
    """Les variables HTTP_PROXY de l'environnement ne sont jamais lues : la recherche part droit vers l'hôte réglé.
    Un mandataire explicite (KERYX_VIRUSTOTAL_PROXY) est utilisé, lui : ici le faux serveur joue le mandataire."""
    proxies = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
    settings.virustotal_url, settings.virustotal_allow_loopback = fake.url, True
    app = create_app(settings)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    set_key(a)
    for name in proxies:                                          # posées après la connexion : seul l'appel sortant les verrait
        monkeypatch.setenv(name, "http://127.0.0.1:9")            # port fermé : si elles étaient lues, la recherche échouerait
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    assert manual(a, EICAR_SHA256).status_code == 201
    assert fake.requests[-1]["path"] == f"/api/v3/files/{EICAR_SHA256}"
    for name in proxies:
        monkeypatch.delenv(name)
    # mandataire explicite : la requête lui parvient en forme absolue, pour un hôte que rien d'autre ne sert
    # (HTTP en clair ; le mode CONNECT vers un hôte HTTPS n'est pas essayé ici)
    settings.virustotal_url, settings.virustotal_proxy = "http://localhost:1", fake.url
    proxied = create_app(settings)
    a = login(proxied, db, "analyst_acme")
    r = manual(a, EICAR_SHA256)
    assert fake.requests[-1]["path"] == f"http://localhost:1/api/v3/files/{EICAR_SHA256}"
    assert r.status_code == 201 and r.json()["summary"]["stats"]["malicious"] == 62


def test_recherche_refusee_sans_accord_du_client(vapp, db, world, analyst, fake):
    """PDIS IV.1.g : sans l'accord enregistré par le manager, aucune empreinte ne part chez VirusTotal."""
    _accord(db, valeur=False)
    avant = len(fake.requests) if hasattr(fake, "requests") else 0
    r = analyst.post("/api/v1/tickets/ACME-1/virustotal", json={"source": "saisie", "hash": "a" * 64})
    assert r.status_code == 403 and "IV.1.g" in r.json()["detail"]
    assert (len(fake.requests) if hasattr(fake, "requests") else 0) == avant
    assert analyst.get("/api/v1/tickets/ACME-1").json()["virustotal"]["autorise"] is False
    m = login(vapp, db, "manager")
    assert m.put("/api/v1/politique/ACME", json={"virustotal_autorise": True}).json()["virustotal_autorise"] is True
    assert analyst.get("/api/v1/tickets/ACME-1").json()["virustotal"]["autorise"] is True
