"""Réversibilité (PDIS IV.5.2.b et f) : export complet d'un client (manager), sans secret, avec manifeste
d'empreintes ; destruction complète après export, l'autre client intact ; droits."""
import hashlib
import io
import json
import zipfile

import pytest
from sqlalchemy import func, select

from keryx import restitution
from keryx.models import AuditEntry, RawAlert, Tenant, Ticket, User

from .conftest import ALERT_CRITICAL, ALERT_SSH_BRUTEFORCE, ingest, login


def _zip(resp):
    return zipfile.ZipFile(io.BytesIO(resp.content))


def test_export_complet_sans_secret(app, db, world, alert):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE)).json()["ticket"]
    ingest(app, world["keys"]["DELTA"], alert(ALERT_CRITICAL))
    a = login(app, db, "analyst_acme")
    a.post(f"/api/v1/tickets/{ref}/comments", json={"body_html": "<p>Commentaire interne</p>"})
    adm = login(app, db, "admin")
    adm.patch("/api/v1/admin/clients/ACME", json={"wazuh_indexer_url": "https://idx.acme.example:9200",
                                                 "wazuh_index_pattern": "wazuh-alerts-*", "wazuh_indexer_source": "manager:acme",
                                                 "wazuh_indexer_user": "lecteur", "wazuh_indexer_password": "MotDePasseSecret!"})
    m = login(app, db, "manager")
    r = m.get("/api/v1/politique/ACME/export")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = _zip(r)
    assert r.headers["x-keryx-sha256"] == hashlib.sha256(r.content).hexdigest()
    manif = json.loads(z.read("manifeste.json"))
    for name, digest in manif["fichiers"].items():
        assert hashlib.sha256(z.read(name)).hexdigest() == digest
    tickets = json.loads(z.read("tickets.json"))
    assert [t["ref"] for t in tickets] == [ref]                                    # rien de DELTA
    assert json.loads(z.read("commentaires.json"))[0]["body_html"].startswith("<p>Commentaire interne")
    assert json.loads(z.read("alertes-brutes.json"))
    tout = b"".join(z.read(n) for n in z.namelist())
    assert b"MotDePasseSecret" not in tout and b"DELTA-" not in tout
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "client.export")).one().details["sha256"]
    for qui in ("admin", "analyst_acme", "client_acme"):
        assert login(app, db, qui).get("/api/v1/politique/ACME/export").status_code == 403


def test_destruction_apres_export(app, db, world, alert, settings):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    ingest(app, world["keys"]["DELTA"], alert(ALERT_CRITICAL))
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    with pytest.raises(ValueError):
        restitution.destroy_client(db, settings, acme, "admin")                    # pas d'export : refus
    restitution.export_bytes(db, settings, acme, "manager")
    db.commit()
    simu = restitution.destroy_client(db, settings, acme, "admin", dry_run=True)
    assert simu["tickets"] == 1 and db.scalar(select(func.count()).select_from(Ticket)) == 2   # simulation : rien
    restitution.destroy_client(db, settings, acme, "admin", dry_run=False)
    db.commit()
    db.expire_all()
    assert db.scalars(select(Tenant).where(Tenant.key == "ACME")).first() is None
    assert [t.ref for t in db.scalars(select(Ticket))] == ["DELTA-1"]
    assert db.scalar(select(func.count()).select_from(RawAlert).where(RawAlert.tenant_id == acme.id)) == 0
    assert db.scalars(select(User).where(User.username == "client_acme")).one().active is False
    assert db.scalars(select(AuditEntry).where(AuditEntry.action == "client.destruction")).one().details["tickets"] == 1
    assert login(app, db, "analyst_acme").get("/api/v1/tickets/DELTA-1").status_code == 404     # toujours cloisonné


def test_proces_verbal_de_destruction(app, db, world, alert, settings, tmp_path):
    """PRIS VI.8.d : le procès-verbal identifie les tickets et les pièces détruits, la date et le mode."""
    import json as _json

    from keryx import cli
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    acme = db.scalars(select(Tenant).where(Tenant.key == "ACME")).one()
    restitution.export_bytes(db, settings, acme, "manager")
    db.commit()
    pv = restitution.proces_verbal(db, acme)
    assert [t["ref"] for t in pv["tickets"]] == ["ACME-1"] and pv["client"] == "ACME"
    sortie = tmp_path / "pv.json"
    import os
    os.environ["KERYX_DATABASE_URL"] = settings.database_url
    os.environ["KERYX_SECRET_KEY"] = settings.secret_key
    os.environ["KERYX_ATTACHMENTS_DIR"] = settings.attachments_dir
    try:
        code = cli.main(["destroy-client", "ACME", "--confirm", "ACME", "--pv", str(sortie)])
    finally:
        for k in ("KERYX_DATABASE_URL", "KERYX_SECRET_KEY", "KERYX_ATTACHMENTS_DIR"):
            os.environ.pop(k, None)
    assert code == 0
    doc = _json.loads(sortie.read_text())
    assert doc["detruit"] is True and doc["date"] and doc["tickets"][0]["ref"] == "ACME-1" and "fichiers" in doc["mode"]
