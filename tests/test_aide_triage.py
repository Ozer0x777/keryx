"""Aide au triage (ADR-0028) : titres courts, écart d'horloge, gravité proposée."""
import copy

from keryx.ingest import TITLE_MAX, short_title

from .conftest import ALERT_SSH_BRUTEFORCE, ingest, login

COMMANDE = ('Powershell process spawned with suspicious command line: "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\'
            'v1.0\\\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA')


def test_titre_court_coupe_sur_un_mot():
    t = short_title(COMMANDE, "GOAD-SRV02")
    desc = t.rsplit(" — ", 1)[0]
    assert len(desc) <= TITLE_MAX + 1 and desc.endswith("…") and t.endswith(" — GOAD-SRV02")
    assert COMMANDE.startswith(desc[:-1])                      # début intact, rien d'inventé
    assert short_title("sshd: brute force", "srv") == "sshd: brute force — srv"
    assert short_title("ligne\n  avec   espaces", "") == "ligne avec espaces — agent inconnu"


def test_titre_court_a_l_ingestion_description_complete_conservee(app, db, world, alert):
    a = copy.deepcopy(ALERT_SSH_BRUTEFORCE)
    a["rule"]["description"] = COMMANDE
    ingest(app, world["keys"]["ACME"], alert(a))
    t = login(app, db, "analyst_acme").get("/api/v1/tickets/ACME-1").json()
    assert len(t["title"]) < 140 and "…" in t["title"]
    assert t["rule"]["description"] == COMMANDE                # texte complet dans le détail
    assert "EncodedCommand" in t["body_html"]


def test_ecart_d_horloge_expose_a_l_equipe_seulement(app, db, world, alert):
    from datetime import timedelta
    from keryx.ids import utcnow
    a = copy.deepcopy(ALERT_SSH_BRUTEFORCE)
    a["timestamp"] = (utcnow() + timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")   # manager en avance
    ingest(app, world["keys"]["ACME"], alert(a))
    t = login(app, db, "analyst_acme").get("/api/v1/tickets/ACME-1").json()
    assert -250 < t["reception_delay_s"] < -230 and t["received_at"]
    c = login(app, db, "client_acme").get("/api/v1/tickets/ACME-1").json()
    assert "reception_delay_s" not in c and "received_at" not in c


def test_proposition_de_gravite_regles():
    from keryx.severity import propose_dommages
    # Grille par défaut : standard = Faible / Moyenne / Élevée ; vital = Élevée / Critique / Critique
    assert propose_dommages("Moyenne", "standard") == "significatifs"
    assert propose_dommages("Critique", "standard") == "graves"            # au plus près : Élevée
    assert propose_dommages("Faible", "vital") == "limites"                # au plus près : Élevée
    assert propose_dommages("Critique", "vital") == "significatifs"        # égalité : la plus faible
    assert propose_dommages(None, "standard") is None and propose_dommages("Faible", "inconnue") is None


def test_proposition_affichee_puis_retenue_d_un_clic(app, db, world, alert):
    from sqlalchemy import select
    from keryx.models import AuditEntry
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    a = login(app, db, "analyst_acme")
    t = a.get("/api/v1/tickets/ACME-1").json()
    p = t["proposition"]
    assert p["criticite"] == t["criticite_initiale"] and p["dommages"] and t["gravite"] is None   # rien d'appliqué seul
    assert login(app, db, "client_acme").get("/api/v1/tickets/ACME-1").json()["proposition"] is None
    r = a.post("/api/v1/tickets/ACME-1/qualification", json={"dommages": p["dommages"], "from_proposal": True})
    assert r.status_code == 200 and r.json()["gravite"] == p["gravite"]
    t = a.get("/api/v1/tickets/ACME-1").json()
    assert t["proposition"] is None                                         # qualifié : plus de proposition
    assert any(e["action"] == "qualification" and e["details"].get("source") == "proposition" for e in t["events"])
    db.rollback()
    last = db.scalars(select(AuditEntry).where(AuditEntry.action == "ticket.qualification").order_by(AuditEntry.seq.desc())).first()
    assert last.details.get("source") == "proposition"


def test_commande_demo(app, db, settings, monkeypatch, capsys):
    from sqlalchemy import select
    from keryx.cli import main as cli_main
    from keryx.models import Ticket, Tenant
    monkeypatch.setenv("KERYX_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KERYX_SECRET_KEY", settings.secret_key)
    assert cli_main(["demo"]) == 0
    assert "10 incidents fictifs" in capsys.readouterr().out
    db.rollback()
    demo = db.scalars(select(Tenant).where(Tenant.key == "DEMO")).one()
    tickets = db.scalars(select(Ticket).where(Ticket.tenant_id == demo.id)).all()
    assert len(tickets) == 10 and {t.criticite_initiale for t in tickets} >= {"Faible", "Critique"}
    assert all(t.ref.startswith("DEMO-") for t in tickets)
    assert cli_main(["demo"]) == 2                                   # pas de doublon
    assert "existe déjà" in capsys.readouterr().err
