"""Réponse aux incidents (référentiel PRIS v3.2) : données structurées du ticket et leurs routes.

- Compréhension de l'incident (VI.5.3.e, VI.7.3.c, VI.7.4.d) : présence de l'attaquant, mode opératoire en huit
  volets, caractérisation de l'attaquant, périmètre.
- Posture (VI.3.b à d) : démarche, jalons, activités, informations à collecter, effectifs, niveau de discrétion
  vis-à-vis de l'attaquant ; en discrétion élevée, aucune recherche en source ouverte ne part de Keryx (VI.5.2.4).
- Cadre du rapport d'analyse (VI.7.1 à VI.7.4) : qualification, activités, équipe, objectifs, synthèse managériale,
  risques critiques, réserves, indicateurs recherchés, interlocuteurs.
- Mesures d'endiguement et procédures d'urgence (VI.5.4) : proposées par l'équipe, décidées par le commanditaire.
- Point de situation (VI.6.a, VI.5.3.a) : ce qui s'est passé sur le ticket depuis une heure donnée.
Le tout est réservé à l'équipe, sauf les mesures d'endiguement, que le client voit et décide.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import audit
from .ids import rfc3339, utcnow
from .models import Attachment, Comment, CrisisEntry, MesureEndiguement, Ticket, TicketEvent, User

TEXTE = 20_000
ACTIVITES = ("REC", "INV", "CODE", "PCI", "CRISE")
ROLES_EQUIPE = ("responsable_equipe", "pilote_investigation", "analyste_reseau", "analyste_systeme",
                "analyste_codes", "gestionnaire_crise", "expert")

# Schéma de chaque bloc : clé -> ("texte", longueur) | ("choix", valeurs) | ("multi", valeurs) | ("oui_non",)
#                                | ("liste", champs, nombre maximal)
SCHEMAS: dict[str, dict] = {
    "comprehension": {
        "attaquant_present": ("choix", ("oui", "non", "inconnu")),
        "mo_compromission_initiale": ("texte", TEXTE), "mo_maintien": ("texte", TEXTE),
        "mo_dissimulation": ("texte", TEXTE), "mo_cartographie": ("texte", TEXTE),
        "mo_elevation_privileges": ("texte", TEXTE), "mo_controle": ("texte", TEXTE),
        "mo_collecte": ("texte", TEXTE), "mo_exfiltration": ("texte", TEXTE),
        "potentiel_attaque": ("texte", TEXTE),
        "niveau_menace": ("choix", ("strategique", "systemique", "hacktiviste", "isolee", "indeterminee")),
        "objectifs_attaquant": ("texte", TEXTE),
        "vecteur_initial": ("texte", TEXTE), "privileges_obtenus": ("texte", TEXTE),
        "ressources_compromises": ("texte", TEXTE), "comptes_compromis": ("texte", TEXTE),
    },
    "posture": {
        "discretion": ("choix", ("eleve", "moyen", "faible")),
        "demarche": ("texte", TEXTE), "jalons": ("texte", TEXTE), "activites": ("texte", TEXTE),
        "informations_a_collecter": ("texte", TEXTE), "effectifs": ("texte", 2000),
        "validee_par": ("texte", 200), "validee_le": ("texte", 40),
    },
    "rapport": {
        "qualifiee": ("oui_non",), "niveau": ("choix", ("substantiel", "eleve")),
        "activites": ("multi", ACTIVITES), "analyse": ("multi", ("systeme", "reseau")),
        "equipe": ("liste", {"nom": 200, "coordonnees": 300, "role": ROLES_EQUIPE, "activites": 500}, 50),
        "objectifs": ("texte", TEXTE), "criteres": ("texte", TEXTE), "perimetre_prestation": ("texte", TEXTE),
        "modalites": ("texte", TEXTE), "dates_lieux": ("texte", TEXTE), "documents": ("texte", TEXTE),
        "synthese_manageriale": ("texte", TEXTE), "risques_critiques": ("texte", TEXTE),
        "endiguement_recommande": ("texte", TEXTE), "reserves": ("texte", TEXTE),
        "ioc_recherches": ("texte", TEXTE), "elements_collectes": ("texte", TEXTE), "resultats": ("texte", TEXTE),
        "interlocuteurs": ("liste", {"nom": 200, "fonction": 200, "entite": 200}, 100),
        "actions_a_poursuivre": ("texte", TEXTE), "points_amelioration": ("texte", TEXTE),
    },
}
ETATS_MESURE = ("proposee", "acceptee", "refusee", "appliquee", "levee")
DECISION_CLIENT = ("acceptee", "refusee")
# Cycle d'une mesure (PRIS VI.5.4) : le commanditaire décide, l'équipe applique puis lève ; une mesure refusée ou
# levée peut être proposée de nouveau quand la situation change (réévaluation, VI.5.4.a).
TRANSITIONS = {"proposee": ("acceptee", "refusee"), "acceptee": ("appliquee",), "appliquee": ("levee",),
               "refusee": ("proposee",), "levee": ("proposee",)}


class MesureIn(BaseModel):
    type: str = "endiguement"
    libelle: str = Field(min_length=3, max_length=1000)


class MesureMajIn(BaseModel):
    etat: str
    commentaire: str | None = Field(default=None, max_length=5000)
    decision_par: str | None = Field(default=None, max_length=200)


def valider(bloc: str, donnees: dict) -> dict:
    """Contrôle un bloc : clés connues seulement, types et choix respectés. Une valeur vide retire la clé."""
    schema = SCHEMAS.get(bloc)
    if schema is None:
        raise HTTPException(404, "Bloc inconnu.")
    if not isinstance(donnees, dict):
        raise HTTPException(422, "Objet attendu.")
    out = {}
    for cle, valeur in donnees.items():
        regle = schema.get(cle)
        if regle is None:
            raise HTTPException(422, f"Champ inconnu : {cle}.")
        if valeur in (None, "", []):
            out[cle] = None
            continue
        sorte = regle[0]
        if sorte == "texte":
            if not isinstance(valeur, str) or len(valeur) > regle[1]:
                raise HTTPException(422, f"{cle} : texte de {regle[1]} caractères au plus.")
            out[cle] = valeur.strip()
        elif sorte == "choix":
            if valeur not in regle[1]:
                raise HTTPException(422, f"{cle} : valeur attendue parmi {', '.join(regle[1])}.")
            out[cle] = valeur
        elif sorte == "multi":
            if not isinstance(valeur, list) or any(v not in regle[1] for v in valeur):
                raise HTTPException(422, f"{cle} : valeurs attendues parmi {', '.join(regle[1])}.")
            out[cle] = [v for v in regle[1] if v in valeur]
        elif sorte == "oui_non":
            if not isinstance(valeur, bool):
                raise HTTPException(422, f"{cle} : vrai ou faux attendu.")
            out[cle] = valeur
        elif sorte == "liste":
            champs, maximum = regle[1], regle[2]
            if not isinstance(valeur, list) or len(valeur) > maximum or any(not isinstance(x, dict) for x in valeur):
                raise HTTPException(422, f"{cle} : liste de {maximum} éléments au plus.")
            lignes = []
            for x in valeur:
                ligne = {}
                for k, v in x.items():
                    borne = champs.get(k)
                    if borne is None:
                        raise HTTPException(422, f"{cle} : champ inconnu {k}.")
                    if isinstance(borne, tuple):
                        if v not in borne:
                            raise HTTPException(422, f"{cle}.{k} : valeur attendue parmi {', '.join(borne)}.")
                    elif not isinstance(v, str) or len(v) > borne:
                        raise HTTPException(422, f"{cle}.{k} : texte de {borne} caractères au plus.")
                    ligne[k] = v.strip() if isinstance(v, str) else v
                if any(ligne.values()):
                    lignes.append(ligne)
            out[cle] = lignes or None
    return out


def discretion_elevee(t: Ticket) -> bool:
    return ((t.pris or {}).get("posture") or {}).get("discretion") == "eleve"


def mesure_vue(m: MesureEndiguement) -> dict:
    return {"id": m.id, "type": m.type, "libelle": m.libelle, "etat": m.etat, "decision_par": m.decision_par,
            "commentaire": m.commentaire, "cree_par": m.cree_par, "cree_le": rfc3339(m.cree_le),
            "maj_par": m.maj_par, "maj_le": rfc3339(m.maj_le)}


def mesures(db: DbSession, t: Ticket) -> list[dict]:
    return [mesure_vue(m) for m in db.scalars(select(MesureEndiguement).where(MesureEndiguement.ticket_id == t.id)
                                                .order_by(MesureEndiguement.cree_le))]


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit
    load_ticket, event = ctx.load_ticket, ctx.event

    @app.put("/api/v1/tickets/{ref}/pris/{bloc}")
    def maj_bloc(ref: str, bloc: str, body: dict, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        valeurs = valider(bloc, body)
        pris = dict(t.pris or {})
        courant = dict(pris.get(bloc) or {})
        for k, v in valeurs.items():
            if v is None:
                courant.pop(k, None)
            else:
                courant[k] = v
        pris[bloc] = courant
        t.pris, t.updated_at = pris, utcnow()
        details = {"champs": sorted(valeurs)}
        if bloc == "posture" and "discretion" in valeurs:
            details["discretion"] = valeurs["discretion"]
        event(db, t, user, f"pris_{bloc}", details)
        commit(db)
        return {"ref": t.ref, "pris": t.pris}

    @app.post("/api/v1/tickets/{ref}/mesures", status_code=201)
    def ajouter_mesure(ref: str, body: MesureIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        ctx.require_open(t)
        if body.type not in ("endiguement", "urgence"):
            raise HTTPException(422, "Type attendu : endiguement ou urgence.")
        m = MesureEndiguement(ticket_id=t.id, tenant_id=t.tenant_id, type=body.type, libelle=body.libelle.strip(),
                              etat="proposee", cree_par=user.username, cree_le=utcnow())
        db.add(m)
        db.flush()
        event(db, t, user, "mesure_proposee", {"id": m.id, "type": m.type, "libelle": m.libelle}, visible_client=True)
        commit(db)
        return {"mesures": mesures(db, t)}

    @app.patch("/api/v1/tickets/{ref}/mesures/{mesure_id}")
    def maj_mesure(ref: str, mesure_id: str, body: MesureMajIn, user: User = Depends(current_user),
                   db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager", "client")
        t = load_ticket(db, user, ref)
        m = db.get(MesureEndiguement, mesure_id[:36])
        if m is None or m.ticket_id != t.id:
            raise HTTPException(404, "Mesure inconnue.")
        if body.etat not in ETATS_MESURE:
            raise HTTPException(422, f"État attendu parmi : {', '.join(ETATS_MESURE)}.")
        if user.role == "client" and body.etat not in DECISION_CLIENT:
            raise HTTPException(403, "Le client accepte ou refuse une mesure proposée.")
        if body.etat not in TRANSITIONS[m.etat]:
            raise HTTPException(409, f"Mesure « {m.etat} » : passage possible vers "
                                     f"{', '.join(TRANSITIONS[m.etat]) or 'aucun état'} seulement.")
        if user.role == "client":
            # La décision d'activer une mesure revient au commanditaire (PRIS VI.5.4.b) : il accepte ou refuse.
            m.decision_par = user.display_name
        elif body.etat in DECISION_CLIENT:
            if not (body.decision_par or "").strip():
                raise HTTPException(422, "Indiquer qui, chez le commanditaire, a pris la décision.")
            m.decision_par = body.decision_par.strip()
        elif body.etat == "proposee":
            m.decision_par = None
        m.etat, m.maj_par, m.maj_le = body.etat, user.username, utcnow()
        if body.commentaire and body.commentaire.strip():
            m.commentaire = body.commentaire.strip()
        event(db, t, user, f"mesure_{m.etat}", {"id": m.id, "libelle": m.libelle, "decision_par": m.decision_par,
                                                 **({"commentaire": m.commentaire} if m.commentaire else {})},
              visible_client=True)
        commit(db)
        return {"mesures": mesures(db, t)}

    @app.get("/api/v1/tickets/{ref}/point-situation")
    def point_situation(ref: str, heures: int = Query(default=24, ge=1, le=24 * 31), user: User = Depends(current_user),
                        db: DbSession = Depends(get_db)):
        """Restitution « à chaud » (PRIS VI.6.a) : activité du ticket depuis `heures`, et état de la compréhension."""
        require_role(user, "analyst", "manager")
        t = load_ticket(db, user, ref)
        depuis = utcnow() - timedelta(hours=heures)
        ev = db.scalars(select(TicketEvent).where(TicketEvent.ticket_id == t.id, TicketEvent.ts >= depuis)
                        .order_by(TicketEvent.ts)).all()
        com = db.scalars(select(Comment).where(Comment.ticket_id == t.id, Comment.created_at >= depuis)
                         .order_by(Comment.created_at)).all()
        pcs = db.scalars(select(Attachment).where(Attachment.ticket_id == t.id, Attachment.created_at >= depuis)
                         .order_by(Attachment.created_at)).all()
        crise = db.scalars(select(CrisisEntry).where(CrisisEntry.ticket_id == t.id, CrisisEntry.created_at >= depuis)
                           .order_by(CrisisEntry.created_at)).all()
        audit.record(db, user.username, "ticket.point_situation", "ticket", t.ref, t.tenant_id, {"heures": heures})
        commit(db)
        return {
            "ref": t.ref, "titre": t.title, "statut": t.status, "depuis": rfc3339(depuis), "genere_le": rfc3339(utcnow()),
            "actions": [{"ts": rfc3339(e.ts), "acteur": e.actor, "action": e.action, "details": e.details} for e in ev],
            "commentaires": [{"ts": rfc3339(c.created_at), "visible_client": c.visible_client} for c in com],
            "pieces": [{"ts": rfc3339(a.created_at), "fichier": a.filename, "sha256": a.sha256,
                        "sensibilite": a.sensitivity} for a in pcs],
            "crise": [{"ts": rfc3339(e.created_at), "type": e.kind, "texte": e.body, "fait": e.done} for e in crise],
            "mesures": mesures(db, t),
            "comprehension": (t.pris or {}).get("comprehension") or {},
            "posture": (t.pris or {}).get("posture") or {},
        }
