"""Import du référentiel MITRE ATT&CK au format STIX 2.1 (fichier « enterprise-attack.json » téléchargé hors de Keryx).

Aucun accès réseau : l'administrateur dépose le fichier. Seuls les objets « attack-pattern » actifs (ni révoqués,
ni dépréciés) portant un identifiant externe MITRE valide sont retenus.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .ids import utcnow
from .mitre import valid_technique
from .models import MitreTechnique


def parse(bundle: dict) -> dict[str, dict]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Fichier STIX 2.1 attendu : un « bundle » contenant des objets.")
    out: dict[str, dict] = {}
    for o in bundle["objects"]:
        if not isinstance(o, dict) or o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", []) if isinstance(r, dict)
                    and r.get("source_name") == "mitre-attack" and valid_technique(str(r.get("external_id", "")))), None)
        if ref is None:
            continue
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                   if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]
        out[ref["external_id"]] = {"name": str(o.get("name", ""))[:200], "tactics": [str(t)[:60] for t in tactics]}
    return out


def import_bundle(db: DbSession, bundle: dict) -> tuple[int, int]:
    """Renvoie (ajoutées, mises à jour)."""
    parsed = parse(bundle)
    if not parsed:
        raise ValueError("Aucune technique ATT&CK exploitable dans ce fichier.")
    existing = {t.technique_id: t for t in db.scalars(select(MitreTechnique))}
    added = updated = 0
    for tid, v in parsed.items():
        row = existing.get(tid)
        if row is None:
            db.add(MitreTechnique(technique_id=tid, name=v["name"], tactics=v["tactics"]))
            added += 1
        elif row.name != v["name"] or row.tactics != v["tactics"]:
            row.name, row.tactics, row.updated_at = v["name"], v["tactics"], utcnow()
            updated += 1
    return added, updated
