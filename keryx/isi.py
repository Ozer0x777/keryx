"""Classification d'un incident selon le modèle d'événement ETSI GS ISI 002 V1.2.1 (2015-11).

[PDIS IV.2.1.y : format de ticket ETSI recommandé ; ETSI GS ISI 002 clause 4.4 (taxonomie en 8 axes) et Annexe B
(dictionnaire des champs) ; clause 7.4 (échange au format IODEF 2.0)] Les valeurs de premier niveau reprennent les
intitulés de l'Annexe B ; chaque axe accepte une précision libre issue du dictionnaire détaillé (Annexe B, sous-listes),
que Keryx ne contraint pas. L'Annexe B précise elle-même que ses listes « ne sont pas exhaustives ».
Trois axes sont obligatoires pour un incident : qui/pourquoi, quoi, statut, et type de cible (clause 4.4).
"""
from __future__ import annotations

from .ids import rfc3339, utcnow

CATEGORIES = {"IEX": "Intrusions et attaques externes", "IMF": "Dysfonctionnements", "IDB": "Comportements internes déviants"}

# Axe → {code: (référence Annexe B, intitulé ETSI)}
AXES: dict[str, dict[str, tuple[str, str]]] = {
    "who_why": {
        "accident": ("B.1.1.1", "Accident"),
        "unwitting_act": ("B.1.1.2", "Unwitting or unintentional act (error)"),
        "carelessness": ("B.1.1.3", "Unawareness or carelessness or irresponsibility"),
        "malicious_act": ("B.1.1.4", "Malicious act"),
    },
    "what": {
        "unauthorized_access": ("B.1.2.1", "Unauthorized access to a system and/or to information"),
        "unauthorized_action": ("B.1.2.2", "Unauthorized action on the information system and/or against the organization"),
        "malware_installation": ("B.1.2.3", "Installation of unauthorized software programs (malware) on a system"),
        "remote_disturbance": ("B.1.2.4", "Information system remote disturbance"),
        "social_engineering": ("B.1.2.5", "Social engineering attacks"),
        "personal_attack": ("B.1.2.6", "Personal attack on organization's personnel or organization disturbance"),
        "physical_intrusion": ("B.1.2.7", "Physical intrusion or illicit action"),
        "illicit_internet_activity": ("B.1.2.8", "Illicit activity carried out on the public Internet (harming an organization)"),
        "various_errors": ("B.1.2.9", "Various errors (administration, handling, programming, general use)"),
        "breakdown": ("B.1.2.10", "Breakdown or malfunction"),
        "environmental_event": ("B.1.2.11", "Environmental events (unavailability caused by a natural disaster)"),
    },
    "status": {
        "underway": ("B.1.4.1", "Security event attempt (or occurrence) underway"),
        "succeeded": ("B.1.4.2", "Succeeded (or performed) security event"),
        "failed": ("B.1.4.3", "Failed security event"),
    },
    "vulnerability": {
        "behavioural": ("B.1.5.1", "Behavioural vulnerability"),
        "software": ("B.1.5.2", "Software vulnerability"),
        "configuration": ("B.1.5.3", "Configuration vulnerability"),
        "general_security": ("B.1.5.4", "General security vulnerability"),
        "conception": ("B.1.5.5", "Conception vulnerability"),
        "material": ("B.1.5.6", "Material vulnerability"),
    },
    "asset": {
        "databases_applications": ("B.1.6.1", "Data bases and applications"),
        "systems": ("B.1.6.2", "Systems"),
        "networks_telecom": ("B.1.6.3", "Networks and telecommunications"),
        "offline_storage": ("B.1.6.4", "Offline storage devices"),
        "end_user_devices": ("B.1.6.5", "End-user devices"),
        "people": ("B.1.6.6", "People"),
        "facilities": ("B.1.6.7", "Facilities and environment"),
    },
    "cia": {
        "confidentiality": ("B.1.7.1", "Loss of confidentiality"),
        "integrity": ("B.1.7.2", "Loss of integrity"),
        "availability": ("B.1.7.3", "Loss of availability"),
    },
    "impact": {
        "direct": ("B.1.8.1", "Direct impact"),
        "indirect": ("B.1.8.2", "Indirect impact"),
    },
}
MANDATORY = ("who_why", "what", "status", "asset")
HOW_AXIS = "how"                 # « comment » : mêmes catégories que « quoi » (B.1.3.x), avec une précision
MULTI = {"vulnerability": 3}     # jusqu'à 3 types de vulnérabilités combinés (B.1.5)
DETAIL_MAX = 200


class IsiError(ValueError):
    pass


def clean(data: dict) -> dict:
    """Valide et normalise une classification. Lève IsiError (message en français) sinon."""
    if not isinstance(data, dict):
        raise IsiError("Classification attendue sous forme d'objet.")
    out: dict = {}
    cat = data.get("category")
    if cat not in (None, "") and cat not in CATEGORIES:
        raise IsiError(f"Catégorie attendue parmi : {', '.join(CATEGORIES)}.")
    if cat:
        out["category"] = cat
    for axis, choices in AXES.items():
        raw = data.get(axis)
        if raw in (None, "", []):
            continue
        values = raw if isinstance(raw, list) else [raw]
        if axis not in MULTI and len(values) != 1:
            raise IsiError(f"Un seul choix est possible pour « {axis} ».")
        if len(values) > MULTI.get(axis, 1):
            raise IsiError(f"« {axis} » accepte au plus {MULTI.get(axis, 1)} choix.")
        bad = [v for v in values if v not in choices]
        if bad:
            raise IsiError(f"Valeur inconnue pour « {axis} » : {bad[0]}. Attendu : {', '.join(choices)}.")
        out[axis] = list(dict.fromkeys(values)) if axis in MULTI else values[0]
    how = data.get(HOW_AXIS)
    if how not in (None, ""):
        if how not in AXES["what"]:
            raise IsiError(f"Valeur inconnue pour « how » : {how}. Attendu : les catégories de « what ».")
        out[HOW_AXIS] = how
    detail = data.get("detail")
    if detail not in (None, ""):
        if not isinstance(detail, dict):
            raise IsiError("Précisions attendues sous forme d'objet (axe → texte).")
        d = {}
        for k, v in detail.items():
            if k not in (*AXES, HOW_AXIS):
                raise IsiError(f"Précision pour un axe inconnu : {k}.")
            if isinstance(v, str) and v.strip():
                d[k] = v.strip()[:DETAIL_MAX]
        if d:
            out["detail"] = d
    return out


def missing(isi: dict | None) -> list[str]:
    return [a for a in MANDATORY if not (isi or {}).get(a)]


def to_iodef(ticket, tenant_name: str, isi: dict, ref_time) -> dict:
    """Document IODEF 2.0 (JSON, RFC 8727) selon les recommandations de ETSI GS ISI 002 §7.4 : version 2.00, formatid
    « ETSI ISI », Incident.purpose = reporting (3), restriction = private (4), IncidentID, ReportTime et GenerationTime.
    Les axes de la taxonomie sont portés par AdditionalData (une entrée par axe, référence de l'Annexe B incluse)."""
    extra = []
    for axis in ("who_why", "what", HOW_AXIS, "status", "vulnerability", "asset", "cia", "impact"):
        if axis not in isi:
            continue
        values = isi[axis] if isinstance(isi[axis], list) else [isi[axis]]
        table = AXES.get(axis, AXES["what"])
        for v in values:
            ref, label = table[v]
            if axis == HOW_AXIS:
                ref = ref.replace("B.1.2.", "B.1.3.")   # « comment » : mêmes catégories, Annexe B.1.3
            extra.append({"dtype": "string", "meaning": f"ETSI-ISI:{axis}", "formatid": ref,
                          "value": f"{label}" + (f" — {isi['detail'][axis]}" if axis in isi.get("detail", {}) else "")})
    if "category" in isi:
        extra.append({"dtype": "string", "meaning": "ETSI-ISI:category", "value": f"{isi['category']} — {CATEGORIES[isi['category']]}"})
    return {
        "version": "2.00", "lang": "fr", "formatid": "ETSI ISI",
        "Incident": [{
            "purpose": "reporting", "restriction": "private", "status": ticket.status,
            "IncidentID": {"id": ticket.ref, "name": "keryx"},
            "ReportTime": rfc3339(ref_time), "GenerationTime": rfc3339(ref_time),
            "DetectTime": rfc3339(ticket.detected_at),
            "Description": [ticket.title],
            "Contact": [{"role": "creator", "type": "organization", "ContactName": ["Keryx"]},
                        {"role": "cc", "type": "organization", "ContactName": [tenant_name]}],
            "AdditionalData": extra + [{"dtype": "string", "meaning": "tlp", "value": ticket.tlp}],
        }],
    }
