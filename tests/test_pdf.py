"""PDF des rapports produits par le serveur (ADR-0036) : mêmes droits et même contenu que les pages imprimables."""
import re

import pytest
from reportlab import rl_config
from sqlalchemy import select

import keryx.pdf as pdf
from keryx.models import AuditEntry

from .conftest import ALERT_SSH_BRUTEFORCE, ALERT_XSS, ingest, login


@pytest.fixture
def lisible(monkeypatch):
    """Polices de base et pages non compressées : le texte se lit tel quel dans le PDF."""
    monkeypatch.setattr(pdf, "_FONTS", {"regular": "Helvetica", "bold": "Helvetica-Bold", "italic": "Helvetica-Oblique",
                                        "mono": "Courier", "unicode": ""})
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def texte(r) -> str:
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF-")
    assert r.headers["cache-control"] == "no-store" and "attachment" in r.headers["content-disposition"]
    brut = r.content.decode("latin-1")
    # Chaînes du PDF : caractères non ASCII en octal (\\351) et parenthèses échappées.
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), brut).replace("\\(", "(").replace("\\)", ")")


def test_rapport_periodique_equipe_et_client(app, db, world, alert, lisible):
    ingest(app, world["keys"]["ACME"], alert(ALERT_SSH_BRUTEFORCE))
    m = texte(login(app, db, "manager").get("/api/v1/reports/period.pdf", params={"client": "ACME"}))
    assert "Rapport d'incidents" in m and "ACME-1" in m and "\xc9ch\xe9ances tenues" in m
    c = login(app, db, "client_acme")
    pc = texte(c.get("/api/v1/reports/period.pdf", params={"client": "ACME"}))
    assert "ACME-1" in pc and "\xc9ch\xe9ances tenues" not in pc          # cibles internes : jamais dans le rapport du client
    assert c.get("/api/v1/reports/period.pdf", params={"client": "DELTA"}).status_code in (403, 404)
    assert login(app, db, "manager").get("/api/v1/reports/period.pdf", params={"client": "ACME", "from": "hier"}).status_code == 422


def test_rapport_incident_point_de_situation_et_analyse(app, db, world, alert, lisible):
    ref = ingest(app, world["keys"]["ACME"], alert(ALERT_XSS)).json()["ticket"]
    a = login(app, db, "analyst_acme")
    # Contenu piège : HTML tronqué, script, caractères réservés du balisage de reportlab
    a.put(f"/api/v1/tickets/{ref}/body", json={"body_html": "<p>Commande <code>a < b & c</code> <b>gras <i>non fermé"
                                                            "<script>alert(1)</script><ul><li>un</li><li>deux</li></ul>"})
    assert a.post(f"/api/v1/tickets/{ref}/crisis", json={"active": True, "reason": "Exfiltration en cours"}).status_code == 200
    assert a.post(f"/api/v1/tickets/{ref}/crisis/entries", json={"kind": "objectif", "body": "Contenir l'attaque"}).status_code == 201
    r = texte(a.get(f"/api/v1/tickets/{ref}/rapport.pdf"))
    assert f"Rapport d'incident {ref}" in r and "Registre des actions" in r
    assert "a < b & c" in r and "alert(1)" in r                              # texte échappé, rendu tel quel, jamais interprété
    texte(a.get(f"/api/v1/tickets/{ref}/point-situation.pdf", params={"heures": 48}))
    an = texte(a.get(f"/api/v1/tickets/{ref}/rapport-analyse.pdf"))
    assert "Qualification de la prestation" in an and "Contenir l'attaque" in an
    # Droits : le client n'a pas ces rapports internes ; un autre client n'existe pas pour l'analyste
    c = login(app, db, "client_acme")
    for path in ("rapport.pdf", "point-situation.pdf", "rapport-analyse.pdf"):
        assert c.get(f"/api/v1/tickets/{ref}/{path}").status_code == 403
    ingest(app, world["keys"]["DELTA"], alert(ALERT_SSH_BRUTEFORCE))
    assert a.get("/api/v1/tickets/DELTA-1/rapport.pdf").status_code == 404
    db.rollback()
    kinds = {e.details.get("rapport") for e in db.scalars(select(AuditEntry).where(AuditEntry.action == "report.pdf"))}
    assert {"incident", "point_situation", "analyse"} <= kinds


def test_caracteres_hors_latin_avec_dejavu(app, db, world, alert):
    """Avec la police de l'image (DejaVu), un titre en cyrillique, en grec ou avec une flèche s'écrit sans erreur."""
    pdf._FONTS = None
    if not pdf.fonts()["unicode"]:
        pytest.skip("police DejaVu absente de cette machine (présente dans l'image Docker)")
    p = pdf.Pdf("Rapport : Привет Ωμέγα → ✓", "sous-titre", "TLP:AMBER", "maintenant")
    p.html("<p>Ligne <b>grasse</b> et 漢字</p><pre>ls -la\n/etc</pre>")
    p.table(["A", "B"], [["x" * 300, "y"]])
    assert p.render().startswith(b"%PDF-")
