"""Criticité initiale (automatique, depuis Wazuh) et gravité qualifiée (analyste).

[PDIS IV.2.1.q] qualification vrai/faux positif, gravité, impact.
[PDIS IV.2.1.e, r, s] échelle définie avec le client (ISO/IEC 27035 recommandée) :
la grille par défaut croise dommages × importance ; chaque client peut avoir la sienne.
Note : la grille par défaut n'a pas été confrontée au texte (payant) de l'ISO/IEC 27035.
"""
from __future__ import annotations

# Niveaux Wazuh 0-16 (documentation « Rules classification »).
_LEVEL_BANDS = ((14, "Critique"), (12, "Élevée"), (10, "Moyenne"), (7, "Faible"))

DOMMAGES = ("limites", "significatifs", "graves")
IMPORTANCES = ("standard", "sensible", "vital")

DEFAULT_GRID: dict[str, dict[str, str]] = {
    "limites":       {"standard": "Faible",  "sensible": "Moyenne", "vital": "Élevée"},
    "significatifs": {"standard": "Moyenne", "sensible": "Élevée",  "vital": "Critique"},
    "graves":        {"standard": "Élevée",  "sensible": "Critique", "vital": "Critique"},
}


def criticite_initiale(level: int, min_level: int = 7) -> str | None:
    """None = sous le seuil, aucun ticket."""
    if level < min_level:
        return None
    for threshold, label in _LEVEL_BANDS:
        if level >= threshold:
            return label
    return "Faible"


def gravite(dommages: str, importance: str, grid: dict | None = None) -> str:
    if dommages not in DOMMAGES:
        raise ValueError(f"dommages invalide : {dommages}")
    if importance not in IMPORTANCES:
        raise ValueError(f"importance invalide : {importance}")
    g = grid or DEFAULT_GRID
    return g[dommages][importance]


_RANK = {"Faible": 1, "Moyenne": 2, "Élevée": 3, "Critique": 4}


def propose_dommages(criticite: str | None, importance: str, grid: dict | None = None) -> str | None:
    """Proposition de dommages pour l'analyste (ADR-0028), jamais appliquée sans son clic : les dommages dont la
    gravité, selon la grille du client et l'importance de l'équipement, est la plus proche de la criticité initiale
    (niveau de la règle Wazuh). À égalité, les dommages les plus faibles : la proposition ne surévalue pas."""
    if criticite not in _RANK or importance not in IMPORTANCES:
        return None
    target = _RANK[criticite]
    return min(DOMMAGES, key=lambda d: (abs(_RANK[gravite(d, importance, grid)] - target), DOMMAGES.index(d)))


def importance_from_alert(alert: dict) -> str:
    """Importance de l'équipement lue dans le label d'agent Wazuh « importance »
    (section <labels> d'ossec.conf, reprise dans les alertes). Par défaut : standard."""
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    labels = agent.get("labels") or alert.get("labels") or {}
    if not isinstance(labels, dict):
        return "standard"
    value = str(labels.get("importance", "")).strip().lower()
    return value if value in IMPORTANCES else "standard"


def is_rex_required(severity: str | None) -> bool:
    return severity in ("Élevée", "Critique")
