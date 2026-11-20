"""Contrôle structurel de l'export IODEF (RFC 7970, binding JSON RFC 8727).

Vérifie les membres obligatoires d'un Incident et le format des dates. Ce n'est PAS une validation contre le
schéma officiel complet : seules les règles de structure dont le texte des RFC est certain sont contrôlées.
"""
from __future__ import annotations

import re

RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
PURPOSES = {"traceback", "mitigation", "reporting", "watch", "other", "ext-value"}


def validate(doc: dict) -> list[str]:
    errors: list[str] = []
    if doc.get("version") != "2.0":
        errors.append("version : « 2.0 » attendu")
    incidents = doc.get("Incident")
    if not isinstance(incidents, list) or not incidents:
        return errors + ["Incident : au moins un incident est obligatoire"]
    for i, inc in enumerate(incidents):
        p = f"Incident[{i}]"
        if inc.get("purpose") not in PURPOSES:
            errors.append(f"{p}.purpose : attribut obligatoire parmi {sorted(PURPOSES)}")
        iid = inc.get("IncidentID")
        if not isinstance(iid, dict) or not iid.get("id") or not iid.get("name"):
            errors.append(f"{p}.IncidentID : identifiant et attribut name obligatoires")
        for k in ("GenerationTime",):
            if not isinstance(inc.get(k), str) or not RFC3339.match(inc[k]):
                errors.append(f"{p}.{k} : date RFC 3339 obligatoire")
        for k in ("DetectTime", "StartTime", "EndTime", "RecoveryTime", "ReportTime"):
            if k in inc and inc[k] is not None and not (isinstance(inc[k], str) and RFC3339.match(inc[k])):
                errors.append(f"{p}.{k} : date RFC 3339 attendue")
        contacts = inc.get("Contact")
        if not isinstance(contacts, list) or not contacts:
            errors.append(f"{p}.Contact : au moins un contact est obligatoire")
        else:
            for j, c in enumerate(contacts):
                if not c.get("role") or not c.get("type"):
                    errors.append(f"{p}.Contact[{j}] : attributs role et type obligatoires")
    return errors
