"""PDF des rapports produits par le serveur (ADR-0036).

Chaque PDF part de la réponse de la route JSON qui alimente la page du rapport, appelée telle quelle : mêmes droits,
même cloisonnement par client, même retrait des données internes pour le client, même trace au journal d'audit. Ce
module ne lit rien d'autre ; il met en page. Une entrée d'audit de plus note la production du PDF.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Query
from fastapi.responses import Response
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session as DbSession

from . import audit
from .ids import utcnow
from .models import User
from .pdf import Pdf, fmt_date

STATUTS = {"nouveau": "Nouveau", "en_evaluation": "En évaluation", "en_reponse": "En réponse", "cloture": "Clôturé",
           "faux_positif": "Faux positif", "retour_experience": "Retour d'expérience"}
VERDICTS = {"vrai_positif_avere": "Vrai positif, incident avéré", "vrai_positif_non_avere": "Vrai positif, non avéré",
            "faux_positif": "Faux positif"}
DISCRETION = {"eleve": "Élevée", "moyen": "Moyenne", "faible": "Faible"}
MENACE = {"strategique": "Stratégique", "systemique": "Systémique", "hacktiviste": "Hacktiviste", "isolee": "Isolée",
          "indeterminee": "Indéterminée"}
PRESENCE = {"oui": "Oui", "non": "Non", "inconnu": "Inconnu"}
ETATS_MESURE = {"proposee": "Proposée", "acceptee": "Acceptée par le commanditaire", "refusee": "Refusée par le commanditaire",
                "appliquee": "Appliquée", "levee": "Levée"}
ROLES_EQUIPE = {"responsable_equipe": "Responsable d'équipe", "pilote_investigation": "Pilote d'investigation",
                "analyste_reseau": "Analyste réseau", "analyste_systeme": "Analyste système", "analyste_codes": "Analyste de codes",
                "expert_pci": "Expert de la gestion de crise", "autre": "Autre"}
# Rapport d'analyse (PRIS v3.2, VI.7) : libellés des rubriques, dans l'ordre de la page de l'interface.
CADRE = [("objectifs", "Objectifs"), ("criteres", "Critères"), ("perimetre_prestation", "Périmètre de la prestation"),
         ("modalites", "Modalités particulières"), ("dates_lieux", "Dates et lieux de la prestation"),
         ("documents", "Documents de référence (référence, version, date)")]
SYNTHESE = [("risques_critiques", "Risques critiques"), ("endiguement_recommande", "Principales mesures d'endiguement recommandées"),
            ("reserves", "Réserves sur les résultats")]
CRISE = [("actions_a_poursuivre", "Actions à initier ou à poursuivre"), ("points_amelioration", "Points positifs et à améliorer")]
RESULTATS = [("ioc_recherches", "Indicateurs de compromission recherchés"), ("elements_collectes", "Éléments collectés et analysés"),
             ("resultats", "Résultats des activités de réponse")]
MODE_OPERATOIRE = [("mo_compromission_initiale", "Compromission initiale"), ("mo_maintien", "Maintien dans le SI"),
                   ("mo_dissimulation", "Dissimulation"), ("mo_cartographie", "Cartographie du SI"),
                   ("mo_elevation_privileges", "Élévation de privilèges"), ("mo_controle", "Contrôle des ressources compromises"),
                   ("mo_collecte", "Collecte d'informations"), ("mo_exfiltration", "Exfiltration d'informations")]
PERIMETRE = [("vecteur_initial", "Vecteur initial de compromission"), ("privileges_obtenus", "Niveau de privilège obtenu par l'attaquant"),
             ("ressources_compromises", "Ressources compromises"), ("comptes_compromis", "Comptes compromis, en particulier d'administration")]


def pdf_response(content: bytes, filename: str) -> Response:
    return Response(content, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})


def register(app, ctx) -> None:
    get_db, current_user, commit = ctx.get_db, ctx.current_user, ctx.commit

    def route(path: str):
        """La fonction de la route JSON de ce chemin, appelée directement (dépendances passées à la main)."""
        for r in app.routes:
            if isinstance(r, APIRoute) and r.path == path and "GET" in r.methods:
                return r.endpoint
        raise RuntimeError(f"route introuvable : {path}")

    def trace(db: DbSession, user: User, quoi: str, ref: str | None, tenant_id: str | None, details: dict | None = None):
        audit.record(db, user.username, "report.pdf", "ticket" if ref else "tenant", ref, tenant_id, {"rapport": quoi, **(details or {})})
        commit(db)

    # ------------------------------------------------------------------ rapport périodique
    @app.get("/api/v1/reports/period.pdf")
    def period_pdf(client: str | None = None, start: str | None = Query(default=None, alias="from"), to: str | None = None,
                   user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        from datetime import date as _date
        try:
            s = _date.fromisoformat(start) if start else None
            e = _date.fromisoformat(to) if to else None
        except ValueError as exc:
            raise HTTPException(422, "Dates attendues au format AAAA-MM-JJ.") from exc
        r = route("/api/v1/reports/period")(client=client, start=s, to=e, user=user, db=db)
        doc = Pdf(f"Rapport d'incidents : {r['client']['name']}", f"Période du {r['period']['from']} au {r['period']['to']}",
                  "TLP:AMBER", fmt_date(r["generated_at"]))
        tot, dl = r["totals"], r["delays"]
        doc.h2("Synthèse")
        pairs = [("Incidents créés", tot["created"]), ("Incidents clos", tot["closed"]), ("Ouverts à ce jour", tot["open"])]
        if "sla" in r:
            sla = r["sla"]
            pairs.append(("Échéances tenues", "—" if sla["rate_percent"] is None else
                          f"{sla['rate_percent']} % ({sla['resolution_within_target']} sur {sla['closed']})"))
        pairs.append(("Délai moyen de résolution", "—" if dl["resolution_hours_avg"] is None else f"{dl['resolution_hours_avg']} h"))
        doc.kv(pairs)
        if r.get("acquittement"):
            doc.h2("Délai d'acquittement")
            doc.p("De la détection à la première action de l'équipe, par criticité.", muted=True)
            doc.table(["Criticité", "Moyenne (min)", "90e centile (min)", "Acquittés", "Non acquittés"],
                      [[c, v["moyenne_min"], v["p90_min"], v["acquittes"], v["non_acquittes"]] for c, v in r["acquittement"].items()],
                      widths=[3, 2, 2, 2, 2])
        doc.h2("Incidents de la période")
        doc.table(["Réf.", "Titre", "Détecté", "Criticité", "Gravité", "Statut", "MITRE"],
                  [[i["ref"], i["title"], fmt_date(i["detected_at"]), i["criticite_initiale"], i["gravite"],
                    STATUTS.get(i["status"], i["status"]), ", ".join(i["mitre"])] for i in r["incidents"]],
                  widths=[2, 6, 3, 2, 2, 2.5, 2.5], vide="Aucun incident sur la période.")
        parc = r.get("parc") or {}
        if parc.get("agents"):
            doc.h2("Parc d'agents Wazuh")
            doc.kv([("Agents", parc["agents"]),
                    ("Disponibilité moyenne", "—" if parc.get("availability_percent") is None else f"{parc['availability_percent']} %"),
                    ("Agents à mettre à jour", parc.get("outdated"))])
        trace(db, user, "periode", None, None, {"client": r["client"]["key"], "from": r["period"]["from"], "to": r["period"]["to"]})
        return pdf_response(doc.render(), f"rapport-{r['client']['key']}-{r['period']['from']}_{r['period']['to']}.pdf")

    # ------------------------------------------------------------------ rapport d'incident
    @app.get("/api/v1/tickets/{ref}/rapport.pdf")
    def ticket_pdf(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        ctx.require_role(user, "analyst", "manager")
        t = route("/api/v1/tickets/{ref}")(ref=ref, complet=True, user=user, db=db)
        s = t.get("synthese") or {}
        doc = Pdf(f"Rapport d'incident {t['ref']}", f"{t['title']} · {t['client']} · statut {STATUTS.get(t['status'], t['status'])}",
                  t["tlp"], fmt_date(utcnow().isoformat()))
        rule = t["rule"]
        doc.kv([("Détecté le", fmt_date(t["detected_at"])), ("Niveau de classification", t.get("niveau_classification")),
                ("Règle Wazuh", f"{rule['id']} (niveau {rule['level']}) : {rule['description']}"),
                ("Équipement", f"{t['agent']['name'] or ''} {t['agent']['ip'] or ''}".strip()),
                ("Collecteur", t.get("collecteur")), ("Criticité initiale", t.get("criticite_initiale")),
                ("Gravité qualifiée", t.get("gravite")), ("Verdict", VERDICTS.get(t.get("verdict"), "À qualifier")),
                ("MITRE ATT&CK", ", ".join(f"{m['id']} {m.get('technique') or ''}".strip() for m in t.get("mitre_detail") or [])),
                ("Occurrences", t.get("occurrences"))])
        for k, titre in (("impact", "Impact constaté"), ("risque", "Risque induit")):
            if t.get(k):
                doc.h2(titre)
                doc.p(t[k])
        doc.h2("Description")
        doc.html(t.get("body_html"))
        for k, titre in (("chronologie", "Chronologie"), ("mode_operatoire", "Mode opératoire"), ("perimetre", "Périmètre"),
                         ("rex_html", "Retour d'expérience")):
            if s.get(k):
                doc.h2(titre)
                doc.html(s[k])
        doc.h2("Registre des actions")
        doc.table(["Date", "Auteur", "Action"], [[fmt_date(e["ts"]), e["actor"], e["action"]] for e in t["events"]], widths=[3, 3, 6])
        o = t.get("occurrences_resume") or {}
        if o.get("nombre"):
            doc.p(f"{o['nombre']} occurrence(s) de l'alerte fusionnée(s) dans ce ticket, du {fmt_date(o['premiere'])} au "
                  f"{fmt_date(o['derniere'])}, non détaillée(s).", muted=True)
        if t["attachments"]:
            doc.h2("Registre des preuves")
            doc.table(["Fichier", "SHA-256", "Collecte", "Méthode"],
                      [[a["filename"], a["sha256"], fmt_date(a.get("collected_at")), a.get("method")] for a in t["attachments"]],
                      widths=[3, 5, 2.5, 3])
        trace(db, user, "incident", t["ref"], None)
        return pdf_response(doc.render(), f"{t['ref']}-rapport.pdf")

    # ------------------------------------------------------------------ point de situation
    @app.get("/api/v1/tickets/{ref}/point-situation.pdf")
    def point_pdf(ref: str, heures: int = Query(default=24, ge=1, le=24 * 31), user: User = Depends(current_user),
                  db: DbSession = Depends(get_db)):
        p = route("/api/v1/tickets/{ref}/point-situation")(ref=ref, heures=heures, user=user, db=db)
        doc = Pdf(f"Point de situation {p['ref']}", f"{p['titre']} · du {fmt_date(p['depuis'])} au {fmt_date(p['genere_le'])}",
                  "", fmt_date(p["genere_le"]))
        doc.h2("Compréhension de l'incident")
        doc.kv([("L'attaquant est-il toujours présent ?", PRESENCE.get(p["comprehension"].get("attaquant_present"))),
                ("Niveau de menace estimé", MENACE.get(p["comprehension"].get("niveau_menace"))),
                ("Niveau de discrétion vis-à-vis de l'attaquant", DISCRETION.get(p["posture"].get("discretion")))])
        doc.h2("Mesures d'endiguement")
        if p["mesures"]:
            doc.bullets([f"{m['libelle']} : {ETATS_MESURE.get(m['etat'], m['etat'])}" for m in p["mesures"]])
        else:
            doc.p("Aucune mesure proposée.", muted=True)
        doc.h2("Activité de la période")
        doc.table(["Date", "Auteur", "Action"], [[fmt_date(a["ts"]), a["acteur"], a["action"]] for a in p["actions"]],
                  widths=[3, 3, 6], vide="Aucune action sur la période.")
        if p["actions_omises"]:
            doc.p(f"{p['actions_omises']} action(s) plus ancienne(s) de la période non reprise(s) ici : voir le registre du ticket.", muted=True)
        doc.p(f"{p['occurrences']} occurrence(s) de l'alerte, {len(p['commentaires'])} commentaire(s), {len(p['pieces'])} "
              f"pièce(s) collectée(s), {len(p['crise'])} entrée(s) de crise sur la période.")
        if p["crise"]:
            doc.h2("Crise")
            doc.bullets([f"{fmt_date(e['ts'])} · {e['type']} : {e['texte']}" for e in p["crise"]])
        trace(db, user, "point_situation", p["ref"], None, {"heures": heures})
        return pdf_response(doc.render(), f"{p['ref']}-point-de-situation.pdf")

    # ------------------------------------------------------------------ rapport d'analyse (PRIS v3.2, VI.7)
    @app.get("/api/v1/tickets/{ref}/rapport-analyse.pdf")
    def analyse_pdf(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        ctx.require_role(user, "analyst", "manager")
        t = route("/api/v1/tickets/{ref}")(ref=ref, complet=True, user=user, db=db)
        crise = route("/api/v1/tickets/{ref}/crisis")(ref=ref, user=user, db=db)["items"]
        p, s = t.get("pris") or {}, t.get("synthese") or {}
        r, c = p.get("rapport") or {}, p.get("comprehension") or {}
        doc = Pdf(f"Rapport d'analyse {t['ref']}", f"{t['title']} · {t['client']} · {t.get('niveau_classification') or 'Non protégé'}",
                  t["tlp"], fmt_date(utcnow().isoformat()))
        doc.h2("1. Qualification de la prestation")
        doc.kv([("Prestation qualifiée", {True: "Oui", False: "Non"}.get(r.get("qualifiee"))),
                ("Niveau de qualification", {"eleve": "Élevé", "substantiel": "Substantiel"}.get(r.get("niveau"))),
                ("Activités de réponse", ", ".join(r.get("activites") or [])),
                ("Type d'analyse", ", ".join({"reseau": "Réseau", "systeme": "Système"}.get(x, x) for x in r.get("analyse") or []))])
        doc.h3("Équipe de réponse")
        doc.table(["Nom", "Coordonnées", "Rôle", "Activités réalisées"],
                  [[m.get("nom"), m.get("coordonnees"), ROLES_EQUIPE.get(m.get("role"), m.get("role")), m.get("activites")]
                   for m in r.get("equipe") or []], widths=[3, 3, 3, 4], vide="Non renseigné.")
        doc.h2("2. Cadre")
        for k, titre in CADRE:
            doc.h3(titre)
            doc.p(r.get(k))
        doc.h2("3. Synthèse managériale")
        doc.p(r.get("synthese_manageriale"))
        doc.kv([("Compromission initiale", fmt_date(s.get("compromission_initiale")) if s.get("compromission_initiale") else None),
                ("Niveau de menace estimé", MENACE.get(c.get("niveau_menace"))),
                ("Objectifs supposés de l'attaquant", c.get("objectifs_attaquant"))])
        for k, titre in SYNTHESE + ([] if not (r.get("actions_a_poursuivre") or r.get("points_amelioration")) else CRISE):
            doc.h3(titre)
            doc.p(r.get(k))
        doc.h2("4. Résultats")
        for k, titre in RESULTATS:
            doc.h3(titre)
            doc.p(r.get(k))
        doc.h3("Compréhension de l'incident")
        doc.kv([("L'attaquant est-il toujours présent ?", PRESENCE.get(c.get("attaquant_present"))),
                ("Niveau de discrétion vis-à-vis de l'attaquant", DISCRETION.get((p.get("posture") or {}).get("discretion")))])
        if s.get("chronologie"):
            doc.h3("Chronologie détaillée")
            doc.html(s["chronologie"])
        doc.h3("Mode opératoire")
        doc.kv([(titre, c.get(k)) for k, titre in MODE_OPERATOIRE])
        if s.get("mode_operatoire"):
            doc.html(s["mode_operatoire"])
        doc.h3("Caractérisation de l'attaquant")
        doc.kv([("Potentiel d'attaque estimé", c.get("potentiel_attaque"))])
        doc.h3("Périmètre de l'incident")
        doc.kv([(titre, c.get(k)) for k, titre in PERIMETRE])
        if s.get("perimetre"):
            doc.html(s["perimetre"])
        doc.h3("Mesures d'endiguement proposées")
        doc.table(["Mesure", "État", "Décision"],
                  [[m["libelle"] + (" (bouton rouge)" if m.get("type") == "urgence" else ""), ETATS_MESURE.get(m["etat"], m["etat"]),
                    m.get("decision_par")] for m in t.get("mesures") or []], widths=[6, 3, 3], vide="Non renseigné.")
        doc.h3("Personnes avec qui le prestataire a interagi")
        doc.table(["Nom", "Fonction", "Entité"], [[x.get("nom"), x.get("fonction"), x.get("entite")] for x in r.get("interlocuteurs") or []],
                  widths=[4, 4, 4], vide="Non renseigné.")
        doc.h2("5. Annexes")
        doc.h3("Registre des informations et supports collectés")
        doc.table(["Description", "Collecte", "Méthode", "Sensibilité", "SHA-256"],
                  [[a.get("description") or a["filename"], fmt_date(a.get("collected_at")), a.get("method"), a.get("sensitivity"), a["sha256"]]
                   for a in t["attachments"]], widths=[4, 2.5, 3, 2, 5], vide="Non renseigné.")
        doc.h3("Registre des actions réalisées")
        doc.table(["Date", "Auteur", "Action"], [[fmt_date(e["ts"]), e["actor"], e["action"]] for e in t["events"]], widths=[3, 3, 6])
        if crise:
            doc.h3("Plan d'action de gestion de crise")
            lignes = []
            for o in [e for e in crise if e["kind"] == "objectif"]:
                lignes.append(o["body"] + (f" (validé par {o['valide_par']})" if o.get("valide_par") else ""))
                lignes += [f"    · {a['body']}" + (" (fait)" if a.get("done") else "") for a in crise
                           if a["kind"] == "action" and a.get("parent_id") == o["id"]]
            lignes += [a["body"] + (" (fait)" if a.get("done") else "") for a in crise if a["kind"] == "action" and not a.get("parent_id")]
            doc.bullets(lignes)
            doc.h3("Registre des actions de gestion de crise")
            doc.table(["Date", "Type", "Description"], [[fmt_date(e["created_at"]), e["kind"], e["body"]] for e in crise], widths=[3, 2, 7])
            sorties = [e for e in crise if e["kind"] == "critere_sortie"]
            doc.h3("Critères de sortie de crise")
            if sorties:
                doc.bullets([f"{e['body']} : {'atteint' if e.get('done') else 'non atteint'}" for e in sorties])
            else:
                doc.p(None)
        doc.h3("Retour d'expérience")
        doc.html(s.get("rex_html"))
        trace(db, user, "analyse", t["ref"], None)
        return pdf_response(doc.render(), f"{t['ref']}-rapport-analyse.pdf")
