"""Conformité avancée (v0.7) : crise, visionneuse d'audit, STIX, rétention. [PRIS VI.5.5.1 ; PDIS IV.2.2.w]"""
import json
from datetime import timedelta

from sqlalchemy import select

from keryx.ids import utcnow
from keryx.models import RawAlert, Ticket

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login


def test_mode_crise_registre_et_droits(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    a = login(app, db, "analyst_acme")
    assert a.post("/api/v1/tickets/ACME-1/crisis/entries", json={"kind": "decision", "body": "x"}).status_code == 409  # pas de crise
    r = a.post("/api/v1/tickets/ACME-1/crisis", json={"active": True, "reason": "exfiltration confirmée"})
    assert r.status_code == 200 and r.json()["active"] is True
    assert a.post("/api/v1/tickets/ACME-1/crisis", json={"active": True, "reason": "encore"}).status_code == 409
    e = a.post("/api/v1/tickets/ACME-1/crisis/entries", json={"kind": "decision", "body": "Isoler le serveur <b>files</b>"})
    assert e.status_code == 201
    act = a.post("/api/v1/tickets/ACME-1/crisis/entries", json={"kind": "action", "body": "Couper le VPN", "owner": "analyst_acme"}).json()["items"][-1]
    assert a.post("/api/v1/tickets/ACME-1/crisis/entries", json={"kind": "bidon", "body": "x"}).status_code == 422
    assert a.patch(f"/api/v1/tickets/ACME-1/crisis/entries/{act['id']}", json={"done": True}).json()["items"][-1]["done"] is True
    dec = e.json()["items"][0]
    assert a.patch(f"/api/v1/tickets/ACME-1/crisis/entries/{dec['id']}", json={"done": True}).status_code == 422
    assert a.get("/api/v1/tickets", params={"crisis": "true"}).json()["items"][0]["crisis"] is True
    # Le client ne voit pas la crise ; clôture de la crise réservée au manager
    assert login(app, db, "client_acme").get("/api/v1/tickets/ACME-1/crisis").status_code == 403
    assert a.post("/api/v1/tickets/ACME-1/crisis", json={"active": False, "reason": "fin"}).status_code == 403
    assert login(app, db, "manager").post("/api/v1/tickets/ACME-1/crisis", json={"active": False, "reason": "résolue"}).json()["active"] is False
    # Cloisonnement
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    assert a.get("/api/v1/tickets/DELTA-1/crisis").status_code == 404


def test_visionneuse_audit_masque_le_contenu_a_ladmin(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.put("/api/v1/tickets/ACME-1/body", json={"body_html": "<p>secret du client</p>"})
    adm = login(app, db, "admin")
    items = adm.get("/api/v1/audit/entries", params={"limit": 200}).json()["items"]
    assert any(i["action"] == "ticket.description" and i["details"] == {"masque": True} for i in items)
    assert "secret du client" not in json.dumps(items) and "version_precedente" not in json.dumps(items)
    assert any(i["action"] == "auth.login_success" and i["details"].get("method") for i in items)  # non masqué
    # Manager : seulement ses clients ; analyste et client : refusé
    m = login(app, db, "manager")
    assert {i["client"] for i in m.get("/api/v1/audit/entries").json()["items"] if i["client"]} == {"ACME", "DELTA"}
    only = login(app, db, "analyst_acme")
    assert only.get("/api/v1/audit/entries").status_code == 403
    # Filtres et pagination
    page = adm.get("/api/v1/audit/entries", params={"limit": 3}).json()
    assert len(page["items"]) == 3 and page["next_before_seq"]
    nxt = adm.get("/api/v1/audit/entries", params={"limit": 3, "before_seq": page["next_before_seq"]}).json()
    assert nxt["items"][0]["seq"] < page["items"][-1]["seq"]
    assert all(i["action"].startswith("ingest") or i["action"].startswith("ticket.create") for i in adm.get("/api/v1/audit/entries", params={"action": "ticket.create"}).json()["items"])
    cp = adm.get("/api/v1/audit/checkpoint").json()
    assert cp["value"] == f"{cp['seq']}:{cp['seal']}" and len(cp["seal"]) == 64


def bundle(*patterns):
    return {"type": "bundle", "id": "bundle--1", "objects": list(patterns)}


def attack(tid, name, tactics, **extra):
    return {"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics], **extra}


def test_import_stix_et_enrichissement_manuel(app, db, world, alert):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    m = login(app, db, "manager")
    data = bundle(attack("T1078", "Valid Accounts", ["defense-evasion", "persistence"]),
                  attack("T1110.003", "Password Spraying", ["credential-access"]),
                  attack("T9999", "Révoquée", ["x"], revoked=True), attack("T8888", "Dépréciée", ["x"], x_mitre_deprecated=True),
                  {"type": "malware", "name": "ignoré"}, {"type": "attack-pattern", "name": "sans identifiant"})
    r = m.post("/api/v1/mitre/import", files={"file": ("a.json", json.dumps(data).encode(), "application/json")})
    assert r.status_code == 200 and r.json() == {"added": 2, "updated": 0, "total": 2}
    again = m.post("/api/v1/mitre/import", files={"file": ("a.json", json.dumps(bundle(attack("T1078", "Valid Accounts (v2)", ["persistence"]))).encode(), "x")})
    assert again.json()["added"] == 0 and again.json()["updated"] == 1
    assert [t["id"] for t in m.get("/api/v1/mitre/techniques", params={"q": "spray"}).json()["items"]] == ["T1110.003"]
    for bad in (b"pas du json", json.dumps({"type": "autre"}).encode(), json.dumps(bundle()).encode()):
        assert m.post("/api/v1/mitre/import", files={"file": ("a.json", bad, "x")}).status_code == 422
    assert login(app, db, "analyst_acme").post("/api/v1/mitre/import", files={"file": ("a.json", b"{}", "x")}).status_code == 403
    # Correction manuelle : nom et tactiques viennent du référentiel
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/mitre", json={"techniques": ["T1078"]})
    t = a.get("/api/v1/tickets/ACME-1").json()["mitre_detail"][0]
    assert t["technique"] == "Valid Accounts (v2)" and t["tactics"] == ["persistence"]


def _purge_autorisee(db, key="ACME"):
    """Les clients conservent leur contexte toute la prestation par défaut (PDIS IV.5.3.6) : la purge se choisit."""
    from sqlalchemy import update
    from keryx.models import Tenant
    db.execute(update(Tenant).where(Tenant.key == key).values(conserver_contexte=False))
    db.commit()


def test_retention_ne_purge_que_les_tickets_clos_en_fin_de_duree(app, db, world, alert):
    _purge_autorisee(db)
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["ACME"], alert(ALERT_CRITICAL))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    old = utcnow() - timedelta(days=30 * 13)
    for ra in db.scalars(select(RawAlert)).all():
        ra.received_at = old
    db.scalars(select(Ticket).where(Ticket.ref == "ACME-1")).one().closed_at = old
    db.commit()
    adm = login(app, db, "admin")
    sim = adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()
    assert sim["total"] == 1 and db.query(RawAlert).count() == 2   # simulation : rien n'est supprimé
    done = adm.post("/api/v1/admin/retention", json={"dry_run": False}).json()
    assert done["total"] == 1
    db.rollback()
    left = db.scalars(select(RawAlert)).all()
    assert len(left) == 1                                            # le ticket ACME-2 est encore ouvert : conservé
    assert any(i["action"] == "retention.purge" for i in adm.get("/api/v1/audit/entries").json()["items"])
    # Rétention propre au client : 6 mois minimum
    assert adm.patch("/api/v1/admin/clients/ACME", json={"retention_months": 3}).status_code == 422
    assert login(app, db, "manager").post("/api/v1/admin/retention", json={}).status_code == 403


def test_duree_de_retention_par_defaut_reglable_par_l_admin(app, db, world, alert, monkeypatch):
    _purge_autorisee(db)
    adm = login(app, db, "admin")
    r = adm.get("/api/v1/admin/settings/retention").json()
    assert r["months"] == 6 and r["source"] == "defaut" and r["minimum"] == 6        # défaut : minimum PDIS
    # Réglage : appliqué aux clients sans durée propre, tracé, borné
    ok = adm.put("/api/v1/admin/settings/retention", json={"months": 24})
    assert ok.status_code == 200 and ok.json() == {"months": 24, "source": "reglage", "minimum": 6, "maximum": 120}
    assert adm.put("/api/v1/admin/settings/retention", json={"months": 5}).status_code == 422
    assert adm.put("/api/v1/admin/settings/retention", json={"months": 121}).status_code == 422
    entry = next(i for i in adm.get("/api/v1/audit/entries").json()["items"] if i["action"] == "settings.retention")
    assert entry["details"]["mois"] == [6, 24]
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "en_evaluation"})
    a.post("/api/v1/tickets/ACME-1/qualification", json={"verdict": "faux_positif"})
    a.post("/api/v1/tickets/ACME-1/status", json={"status": "faux_positif", "reason": "Alerte sans risque, vérifiée par l analyste."})
    old = utcnow() - timedelta(days=30 * 13)               # 13 mois : au-delà de 6, en deçà de 24
    for ra in db.scalars(select(RawAlert)).all():
        ra.received_at = old
    db.scalars(select(Ticket).where(Ticket.ref == "ACME-1")).one().closed_at = old
    db.commit()
    assert adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()["total"] == 0      # 24 mois : rien à purger
    adm.patch("/api/v1/admin/clients/ACME", json={"retention_months": 6})                          # durée propre au client
    assert adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()["total"] == 1
    adm.patch("/api/v1/admin/clients/ACME", json={"retention_months": None})
    # Retour au minimum, puis seul l'Admin peut lire ou changer
    back = adm.put("/api/v1/admin/settings/retention", json={"months": None}).json()
    assert back["months"] == 6 and back["source"] == "defaut"
    assert adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()["total"] == 1
    for who in ("manager", "analyst_acme", "client_acme"):
        c = login(app, db, who)
        assert c.get("/api/v1/admin/settings/retention").status_code == 403
        assert c.put("/api/v1/admin/settings/retention", json={"months": 7}).status_code == 403


def test_contexte_conserve_toute_la_prestation_par_defaut(app, db, world, alert):
    """PDIS IV.5.3.6 : sans choix explicite de l'Admin, aucune alerte brute d'un client n'est purgée."""
    from datetime import timedelta

    from sqlalchemy import select, update

    from keryx.ids import utcnow
    from keryx.models import RawAlert, Ticket
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    vieux = utcnow() - timedelta(days=3000)
    db.execute(update(Ticket).values(status="cloture", closed_at=vieux))
    db.execute(update(RawAlert).values(received_at=vieux))
    db.commit()
    adm = login(app, db, "admin")
    r = adm.post("/api/v1/admin/retention", json={"dry_run": False}).json()
    assert r["total"] == 0 and next(i for i in r["items"] if i["client"] == "ACME")["conserve"] is True
    db.expire_all()
    assert db.scalars(select(RawAlert)).all()
    assert adm.get("/api/v1/admin/clients").json()["items"][0]["conserver_contexte"] is True
    assert adm.patch("/api/v1/admin/clients/ACME", json={"conserver_contexte": False}).status_code == 200
    r = adm.post("/api/v1/admin/retention", json={"dry_run": True}).json()
    assert r["total"] == 1, r
