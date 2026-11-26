"""Politique du client (ADR-0033, ADR-0032), réglée par le manager pour les clients dont il a la charge : TLP plancher,
délai d'acquittement dans le rapport remis au client.

Les tickets et les pièces d'un client naissent à son TLP plancher ; un analyste ne peut pas descendre en dessous, un
manager le peut sur un ticket avec un motif tracé (keryx/api.py, qualification). Relever le plancher relève les tickets
ouverts qui sont en dessous ; le baisser ne baisse aucun ticket. Tout est inscrit au journal d'audit.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import audit
from .ids import rfc3339, utcnow
from .astreinte import CRITICITES, DELAIS_DEFAUT
from .models import NIVEAUX_CLASSIFICATION, TLP, OnCallChannel, Tenant, Ticket, TicketEvent, User, tlp_rang

OUVERTS = ("nouveau", "en_evaluation", "en_reponse")


class PolitiqueIn(BaseModel):
    """Seuls les champs envoyés changent."""
    tlp_plancher: str | None = Field(default=None, max_length=20)
    acquittement_rapport: bool | None = None
    # Contenu du ticket (PDIS IV.2.1.w)
    niveau_classification_defaut: str | None = Field(default=None, max_length=40)
    version_regles: str | None = Field(default=None, max_length=120)
    # Moyen secondaire de notification (PDIS IV.2.3.b)
    notif_secours_canal_id: str | None = Field(default=None, max_length=36)
    # Astreinte (ADR-0032)
    astreinte_active: bool | None = None
    astreinte_criticites: list[str] | None = Field(default=None, max_length=4)
    astreinte_delais: dict[str, int] | None = None
    astreinte_canal_id: str | None = Field(default=None, max_length=36)
    escalade_canal_id: str | None = Field(default=None, max_length=36)
    # Battement de cœur (ADR-0032, partie 3)
    battement_active: bool | None = None
    battement_periode_min: int | None = Field(default=None, ge=1, le=60)
    battement_delai_min: int | None = Field(default=None, ge=2, le=1440)


ESSAI_SECOURS_JOURS = 182      # PDIS IV.2.3.b : moyen secondaire testé au minimum tous les six mois


def secours_vue(t: Tenant) -> dict:
    from .ids import as_utc
    teste = t.notif_secours_teste_at
    en_retard = bool(t.notif_secours_canal_id) and (teste is None or (utcnow() - as_utc(teste)).days >= ESSAI_SECOURS_JOURS)
    return {"canal_id": t.notif_secours_canal_id, "teste_le": rfc3339(teste), "essai_en_retard": en_retard}


def battement_vue(t: Tenant) -> dict:
    return {"active": bool(t.battement_active), "periode_min": int(t.battement_periode_min or 5),
            "delai_min": int(t.battement_delai_min or 15), "dernier": rfc3339(t.battement_at),
            "source": t.battement_source, "manquant_depuis": rfc3339(t.battement_manquant_at)}


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit
    settings = ctx.settings

    def vue(t: Tenant) -> dict:
        return {"key": t.key, "name": t.name, "tlp_plancher": t.tlp_plancher,
                "niveau_classification_defaut": t.niveau_classification_defaut or "Non protégé",
                "version_regles": t.version_regles,
                "notif_secours": secours_vue(t),
                "acquittement_rapport": bool(t.acquittement_rapport),
                "astreinte": {"active": bool(t.astreinte_active),
                              "criticites": list(t.astreinte_criticites or ["Critique"]),
                              "delais": {**DELAIS_DEFAUT, **(t.astreinte_delais or {})},
                              "canal_id": t.astreinte_canal_id, "escalade_canal_id": t.escalade_canal_id},
                "battement": battement_vue(t)}

    @app.get("/api/v1/politique")
    def politiques(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "manager")
        # Le manager voit le nom et le type des canaux actifs, jamais leur adresse.
        canaux = db.scalars(select(OnCallChannel).where(OnCallChannel.active.is_(True)).order_by(OnCallChannel.name)).all()
        return {"items": [vue(t) for t in sorted(user.tenants, key=lambda t: t.key)], "tlp": list(TLP),
                "niveaux_classification": list(NIVEAUX_CLASSIFICATION),
                "criticites": list(CRITICITES), "canaux": [{"id": c.id, "name": c.name, "kind": c.kind} for c in canaux]}

    def canal(db: DbSession, canal_id: str | None) -> str | None:
        if not canal_id:
            return None
        c = db.get(OnCallChannel, canal_id)
        if c is None or not c.active:
            raise HTTPException(422, "Canal d'astreinte inconnu ou désactivé.")
        return c.id

    def regler_astreinte(db: DbSession, tenant: Tenant, body: PolitiqueIn) -> dict:
        sent = body.model_fields_set
        avant = {"active": bool(tenant.astreinte_active), "criticites": tenant.astreinte_criticites,
                 "delais": tenant.astreinte_delais, "canal": tenant.astreinte_canal_id, "escalade": tenant.escalade_canal_id}
        if "astreinte_criticites" in sent:
            crits = body.astreinte_criticites or []
            if any(c not in CRITICITES for c in crits):
                raise HTTPException(422, f"Criticités attendues parmi : {', '.join(CRITICITES)}.")
            tenant.astreinte_criticites = [c for c in CRITICITES if c in crits]
        if "astreinte_delais" in sent:
            delais = body.astreinte_delais or {}
            if any(k not in CRITICITES or not 1 <= int(v) <= 1440 for k, v in delais.items()):
                raise HTTPException(422, "Délai d'escalade attendu entre 1 et 1440 minutes, par criticité.")
            tenant.astreinte_delais = {**DELAIS_DEFAUT, **{k: int(v) for k, v in delais.items()}}
        if "astreinte_canal_id" in sent:
            tenant.astreinte_canal_id = canal(db, body.astreinte_canal_id)
        if "escalade_canal_id" in sent:
            tenant.escalade_canal_id = canal(db, body.escalade_canal_id)
        if body.astreinte_active is not None:
            tenant.astreinte_active = body.astreinte_active
        if tenant.astreinte_active:
            if not tenant.astreinte_canal_id:
                raise HTTPException(422, "Choisir le canal d'astreinte avant d'activer l'astreinte de ce client.")
            if not tenant.astreinte_criticites:
                tenant.astreinte_criticites = ["Critique"]
        apres = {"active": bool(tenant.astreinte_active), "criticites": tenant.astreinte_criticites,
                 "delais": tenant.astreinte_delais, "canal": tenant.astreinte_canal_id, "escalade": tenant.escalade_canal_id}
        return {"astreinte_avant": avant, "astreinte": apres} if avant != apres else {}

    def regler_battement(tenant: Tenant, body: PolitiqueIn) -> dict:
        avant = {"active": bool(tenant.battement_active), "periode": tenant.battement_periode_min,
                 "delai": tenant.battement_delai_min}
        if body.battement_periode_min is not None:
            tenant.battement_periode_min = body.battement_periode_min
        if body.battement_delai_min is not None:
            tenant.battement_delai_min = body.battement_delai_min
        if int(tenant.battement_delai_min or 15) < 2 * int(tenant.battement_periode_min or 5):
            raise HTTPException(422, "Le délai d'alerte du battement doit valoir au moins deux périodes : un battement "
                                     "retardé ou perdu ne doit pas suffire à donner l'alerte.")
        if body.battement_active is not None and body.battement_active != bool(tenant.battement_active):
            tenant.battement_active = body.battement_active
            # Le délai court depuis l'activation : un client jamais branché est signalé, pas ignoré.
            tenant.battement_depuis = utcnow() if body.battement_active else None
            tenant.battement_manquant_at = None
        apres = {"active": bool(tenant.battement_active), "periode": tenant.battement_periode_min,
                 "delai": tenant.battement_delai_min}
        return {"battement_avant": avant, "battement": apres} if avant != apres else {}

    @app.post("/api/v1/politique/{client}/essai-secours")
    def essai_secours(client: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Essai du moyen secondaire de notification (PDIS IV.2.3.b), sans donnée de ticket, inscrit au registre."""
        import json as _json
        from . import astreinte
        from .models import Notification
        require_role(user, "manager")
        tenant = next((t for t in user.tenants if t.key == client.upper()), None)
        if tenant is None:
            raise HTTPException(404, "Client inconnu.")
        tenant = db.get(Tenant, tenant.id)
        c = db.get(OnCallChannel, tenant.notif_secours_canal_id) if tenant.notif_secours_canal_id else None
        if c is None or not c.active:
            raise HTTPException(422, "Aucun moyen secondaire actif pour ce client.")
        text = f"[Keryx] Essai du moyen de notification secondaire du client {tenant.key} : aucune action demandée."
        msg = {"subject": f"[Keryx] Essai du moyen secondaire ({tenant.key})", "text": text,
               "data": {"type": "keryx.essai_notification", "client": tenant.key}}
        try:
            code, statut, erreur = astreinte.deliver(settings, ctx.box, c, msg), "envoye", None
        except astreinte.DeliveryError as exc:
            code, statut, erreur = exc.http_status, "echec", exc.reason
        db.add(Notification(tenant_id=tenant.id, ticket_id=None, channel=c.kind[:16], recipient=c.name[:200],
                            content=_json.dumps(msg, ensure_ascii=False), status=statut, attempts=1, canal_id=c.id,
                            motif="essai_secours", http_status=code))
        if statut == "envoye":
            tenant.notif_secours_teste_at = utcnow()
        audit.record(db, user.username, "notification.essai_secours", "tenant", tenant.key, tenant.id,
                     {"canal": c.name, "statut": statut, "code": code, **({"erreur": erreur} if erreur else {})})
        commit(db)
        return {"statut": statut, "code": code, **({"erreur": erreur} if erreur else {}), "notif_secours": secours_vue(tenant)}

    @app.get("/api/v1/battements")
    def battements(user: User = Depends(current_user)):
        """État de la chaîne Wazuh vers Keryx des clients de l'équipe (bandeau de l'interface)."""
        require_role(user, "analyst", "manager")
        return {"items": [{"key": t.key, "name": t.name, **battement_vue(t)}
                          for t in sorted(user.tenants, key=lambda t: t.key) if t.battement_active]}

    @app.put("/api/v1/politique/{client}")
    def regler(client: str, body: PolitiqueIn, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "manager")
        tenant = next((t for t in user.tenants if t.key == client.upper()), None)
        if tenant is None:
            raise HTTPException(404, "Client inconnu.")       # même réponse qu'un client inexistant
        tenant = db.get(Tenant, tenant.id)
        sent = body.model_fields_set
        nouveau = (body.tlp_plancher or None) if "tlp_plancher" in sent else tenant.tlp_plancher
        if nouveau is not None and nouveau not in TLP:
            raise HTTPException(422, f"Marquage attendu parmi : {', '.join(TLP)}.")
        avant, rapport_avant = tenant.tlp_plancher, bool(tenant.acquittement_rapport)
        tenant.tlp_plancher = nouveau
        if body.acquittement_rapport is not None:
            tenant.acquittement_rapport = body.acquittement_rapport
        trace_astreinte = {**regler_astreinte(db, tenant, body), **regler_battement(tenant, body)}
        if "niveau_classification_defaut" in sent:
            if body.niveau_classification_defaut not in NIVEAUX_CLASSIFICATION:
                raise HTTPException(422, f"Niveau de classification attendu parmi : {', '.join(NIVEAUX_CLASSIFICATION)}.")
            trace_astreinte["niveau_classification_defaut"] = tenant.niveau_classification_defaut = body.niveau_classification_defaut
        if "version_regles" in sent:
            trace_astreinte["version_regles"] = tenant.version_regles = (body.version_regles or "").strip() or None
        if "notif_secours_canal_id" in sent and body.notif_secours_canal_id != tenant.notif_secours_canal_id:
            tenant.notif_secours_canal_id = canal(db, body.notif_secours_canal_id)
            tenant.notif_secours_teste_at = None          # nouveau moyen : pas encore essayé
            trace_astreinte["notif_secours_canal_id"] = tenant.notif_secours_canal_id
        releves = []
        if tlp_rang(nouveau) > tlp_rang(avant):
            # Plancher relevé : les tickets ouverts en dessous montent (plus restrictif, sans risque), chacun tracé.
            now = utcnow()
            for t in db.scalars(select(Ticket).where(Ticket.tenant_id == tenant.id, Ticket.status.in_(OUVERTS))):
                if tlp_rang(t.tlp) < tlp_rang(nouveau):
                    db.add(TicketEvent(ticket_id=t.id, actor=user.username, action="tlp_releve",
                                       details={"de": t.tlp, "vers": nouveau, "plancher": nouveau}))
                    t.tlp, t.updated_at = nouveau, now
                    releves.append(t.ref)
        audit.record(db, user.username, "client.politique", "tenant", tenant.key, tenant.id,
                     {"tlp_plancher_avant": avant, "tlp_plancher": nouveau, "tickets_releves": len(releves),
                      "acquittement_rapport_avant": rapport_avant,
                      "acquittement_rapport": bool(tenant.acquittement_rapport), **trace_astreinte})
        commit(db)
        return {**vue(tenant), "tickets_releves": releves}
