"""Cycle de vie d'un ticket, aligné sur les phases ISO/IEC 27035-1.

Règles :
- la qualification (verdict) est obligatoire avant toute sortie de l'évaluation [PDIS IV.2.1.q] ;
- « faux_positif » exige le verdict faux_positif ; « en_reponse » exige un vrai positif ;
- un incident de gravité Élevée ou Critique doit passer par « retour_experience »
  après clôture (ISO/IEC 27035 : tirer les enseignements ; ISO 27002 5.27).
"""
from __future__ import annotations

TRANSITIONS: dict[str, set[str]] = {
    "nouveau": {"en_evaluation"},
    "en_evaluation": {"faux_positif", "en_reponse"},
    "en_reponse": {"cloture"},
    "cloture": {"retour_experience"},
    "faux_positif": set(),
    "retour_experience": set(),
}


class TransitionError(ValueError):
    pass


def check_transition(current: str, target: str, verdict: str | None, rex_required: bool,
                     rex_html: str | None = None) -> None:
    if target not in TRANSITIONS.get(current, set()):
        raise TransitionError(f"Transition interdite : {current} → {target}")
    if target == "faux_positif" and verdict != "faux_positif":
        raise TransitionError("Qualifier le ticket en faux positif avant de le clore comme tel.")
    if target == "en_reponse" and verdict not in ("vrai_positif_avere", "vrai_positif_non_avere"):
        raise TransitionError("Qualifier le ticket en vrai positif avant de passer en réponse.")
    if target == "retour_experience" and not (rex_html or "").strip():
        raise TransitionError("Rédiger le retour d'expérience avant de clore cette étape.")


def rex_pending(status: str, rex_required: bool) -> bool:
    """Un incident Élevé/Critique clôturé sans retour d'expérience reste « en attente de REX »."""
    return status == "cloture" and rex_required


def is_open(status: str) -> bool:
    return status in ("nouveau", "en_evaluation", "en_reponse")
