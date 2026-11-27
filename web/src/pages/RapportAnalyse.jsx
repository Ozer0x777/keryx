import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { CHAMPS, DISCRETION, ETATS_MESURE, MENACE, PRESENCE, ROLES_EQUIPE } from '../components/Pris.jsx'
import Html from '../components/Html.jsx'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'

// Rapport d'analyse de réponse aux incidents (PRIS v3.2, VI.7), imprimable : qualification, cadre, synthèse
// managériale, résultats, annexes. Il reprend les données du ticket (synthèse, registres, crise, retour d'expérience)
// et le cadre saisi dans « Réponse aux incidents ». Un champ non renseigné est signalé, jamais inventé.
const vide = <span className="muted">{tr('Non renseigné')}</span>
const label = (bloc, k) => (CHAMPS[bloc].find((x) => x[0] === k) || [k, k])[1]

// Occurrences d'alerte fusionnées dans le ticket : résumées (nombre, première, dernière), jamais listées une à une.
export function Occurrences({ o }) {
  if (!o || !o.nombre) return null
  return <p className="muted">{tr("{n} occurrence(s) de l'alerte fusionnée(s) dans ce ticket, du {a} au {b}, non détaillée(s).", { n: o.nombre, a: formatUtc(o.premiere), b: formatUtc(o.derniere) })}</p>
}

function Texte({ v }) {
  return v ? <p className="prewrap">{v}</p> : <p>{vide}</p>
}

export default function RapportAnalyse() {
  const { ref } = useParams()
  const enc = encodeURIComponent(ref)
  const [t, setT] = useState(null)
  const [crise, setCrise] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api(`/tickets/${enc}`, { params: { complet: true } }).then(setT).catch((e) => setError(e.message))
    api(`/tickets/${enc}/crisis`).then(setCrise).catch(() => setCrise({ items: [] }))
  }, [enc])
  if (error) return <p className="error" role="alert">{error}</p>
  if (!t || !crise) return <p className="loading">{tr('Chargement…')}</p>
  const p = t.pris || {}
  const r = p.rapport || {}
  const c = p.comprehension || {}
  const s = t.synthese || {}
  const crit = (k) => crise.items.filter((e) => e.kind === k)
  return (
    <>
      <div className="row gap noprint" style={{ marginBottom: 12 }}>
        <Link to={`/tickets/${enc}`}>{tr('← Retour au ticket')}</Link>
        <button type="button" onClick={() => window.print()}>{tr('Imprimer / PDF')}</button>
      </div>
      <article className="report card section" aria-label={tr("Rapport d'analyse")}>
        <h1>{tr("Rapport d'analyse")} — {t.ref}</h1>
        <p className="muted">{t.title} · {t.client} · {t.tlp} · {tr(t.niveau_classification || 'Non protégé')} · {tr('généré le {d}', { d: formatUtc(new Date().toISOString()) })}</p>

        <h2>{tr('1. Qualification de la prestation')}</h2>
        <dl className="kv">
          <dt>{tr('Prestation qualifiée')}</dt><dd>{r.qualifiee === true ? tr('Oui') : r.qualifiee === false ? tr('Non') : vide}</dd>
          <dt>{tr('Niveau de qualification')}</dt><dd>{r.niveau ? tr(r.niveau === 'eleve' ? 'Élevé' : 'Substantiel') : vide}</dd>
          <dt>{tr('Activités de réponse')}</dt><dd>{(r.activites || []).join(', ') || vide}</dd>
          <dt>{tr("Type d'analyse")}</dt><dd>{(r.analyse || []).map((x) => tr(x === 'reseau' ? 'Réseau' : 'Système')).join(', ') || vide}</dd>
        </dl>
        <h3>{tr('Équipe de réponse')}</h3>
        {(r.equipe || []).length === 0 ? <p>{vide}</p> : (
          <table className="grid"><thead><tr><th scope="col">{tr('Nom')}</th><th scope="col">{tr('Coordonnées')}</th><th scope="col">{tr('Rôle')}</th><th scope="col">{tr('Activités réalisées')}</th></tr></thead>
            <tbody>{r.equipe.map((m, i) => <tr key={i}><td>{m.nom}</td><td>{m.coordonnees}</td><td>{ROLES_EQUIPE[m.role] || m.role}</td><td>{m.activites}</td></tr>)}</tbody></table>)}

        <h2>{tr('2. Cadre')}</h2>
        {['objectifs', 'criteres', 'perimetre_prestation', 'modalites', 'dates_lieux', 'documents'].map((k) => <div key={k}><h3>{label('rapport', k)}</h3><Texte v={r[k]} /></div>)}

        <h2>{tr('3. Synthèse managériale')}</h2>
        <Texte v={r.synthese_manageriale} />
        <dl className="kv">
          <dt>{tr('Compromission initiale')}</dt><dd>{s.compromission_initiale ? formatUtc(s.compromission_initiale) : vide}</dd>
          <dt>{tr('Niveau de menace estimé')}</dt><dd>{MENACE[c.niveau_menace] || vide}</dd>
          <dt>{tr("Objectifs supposés de l'attaquant")}</dt><dd>{c.objectifs_attaquant || vide}</dd>
        </dl>
        {['risques_critiques', 'endiguement_recommande', 'reserves'].map((k) => <div key={k}><h3>{label('rapport', k)}</h3><Texte v={r[k]} /></div>)}
        {(r.actions_a_poursuivre || r.points_amelioration) && ['actions_a_poursuivre', 'points_amelioration'].map((k) => <div key={k}><h3>{label('rapport', k)}</h3><Texte v={r[k]} /></div>)}

        <h2>{tr('4. Résultats')}</h2>
        {['ioc_recherches', 'elements_collectes', 'resultats'].map((k) => <div key={k}><h3>{label('rapport', k)}</h3><Texte v={r[k]} /></div>)}
        <h3>{tr("Compréhension de l'incident")}</h3>
        <dl className="kv">
          <dt>{tr("L'attaquant est-il toujours présent ?")}</dt><dd>{PRESENCE[c.attaquant_present] || vide}</dd>
          <dt>{tr("Niveau de discrétion vis-à-vis de l'attaquant")}</dt><dd>{DISCRETION[(p.posture || {}).discretion] || vide}</dd>
        </dl>
        {s.chronologie ? <><h3>{tr('Chronologie détaillée')}</h3><Html html={s.chronologie} /></> : null}
        <h3>{tr('Mode opératoire')}</h3>
        <dl className="kv">{CHAMPS.comprehension.filter(([k]) => k.startsWith('mo_')).map(([k, l]) => <div key={k}><dt>{l.replace(/^.*: /, '')}</dt><dd className="prewrap">{c[k] || vide}</dd></div>)}</dl>
        {s.mode_operatoire && <Html html={s.mode_operatoire} />}
        <h3>{tr("Caractérisation de l'attaquant")}</h3>
        <dl className="kv"><dt>{tr("Potentiel d'attaque estimé")}</dt><dd className="prewrap">{c.potentiel_attaque || vide}</dd></dl>
        <h3>{tr("Périmètre de l'incident")}</h3>
        <dl className="kv">{['vecteur_initial', 'privileges_obtenus', 'ressources_compromises', 'comptes_compromis'].map((k) => <div key={k}><dt>{label('comprehension', k)}</dt><dd className="prewrap">{c[k] || vide}</dd></div>)}</dl>
        {s.perimetre && <Html html={s.perimetre} />}
        <h3>{tr("Mesures d'endiguement proposées")}</h3>
        {(t.mesures || []).length === 0 ? <p>{vide}</p> : (
          <table className="grid"><thead><tr><th scope="col">{tr('Mesure')}</th><th scope="col">{tr('État')}</th><th scope="col">{tr('Décision')}</th></tr></thead>
            <tbody>{t.mesures.map((m) => <tr key={m.id}><td>{m.libelle}{m.type === 'urgence' ? ` (${tr('bouton rouge')})` : ''}</td><td>{ETATS_MESURE[m.etat]}</td><td>{m.decision_par || '—'}</td></tr>)}</tbody></table>)}
        <h3>{tr('Personnes avec qui le prestataire a interagi')}</h3>
        {(r.interlocuteurs || []).length === 0 ? <p>{vide}</p> : (
          <table className="grid"><thead><tr><th scope="col">{tr('Nom')}</th><th scope="col">{tr('Fonction')}</th><th scope="col">{tr('Entité')}</th></tr></thead>
            <tbody>{r.interlocuteurs.map((x, i) => <tr key={i}><td>{x.nom}</td><td>{x.fonction}</td><td>{x.entite}</td></tr>)}</tbody></table>)}

        <h2>{tr('5. Annexes')}</h2>
        <h3>{tr('Registre des informations et supports collectés')}</h3>
        {t.attachments.length === 0 ? <p>{vide}</p> : (
          <table className="grid"><thead><tr><th scope="col">{tr('Description')}</th><th scope="col">{tr('Collecte')}</th><th scope="col">{tr('Méthode')}</th><th scope="col">{tr('Sensibilité')}</th><th scope="col">{tr('SHA-256')}</th></tr></thead>
            <tbody>{t.attachments.map((a) => <tr key={a.id}><td>{a.description || a.filename}</td><td className="mono small">{formatUtc(a.collected_at)}</td><td>{a.method}</td><td>{a.sensitivity}</td><td className="mono small">{a.sha256}</td></tr>)}</tbody></table>)}
        <h3>{tr('Registre des actions réalisées')}</h3>
        <table className="grid"><thead><tr><th scope="col">{tr('Date')}</th><th scope="col">{tr('Auteur')}</th><th scope="col">{tr('Action')}</th></tr></thead>
          <tbody>{t.events.map((e, i) => <tr key={i}><td className="mono small">{formatUtc(e.ts)}</td><td>{e.actor}</td><td>{e.action}</td></tr>)}</tbody></table>
        <Occurrences o={t.occurrences_resume} />
        {crise.items.length > 0 && <>
          <h3>{tr("Plan d'action de gestion de crise")}</h3>
          <ul>{crit('objectif').map((o) => (
            <li key={o.id}><strong>{o.body}</strong>{o.valide_par ? ` — ${tr('validé par {who}', { who: o.valide_par })}` : ''}
              <ul>{crise.items.filter((a) => a.kind === 'action' && a.parent_id === o.id).map((a) => <li key={a.id}>{a.body}{a.owner ? ` — ${a.owner}` : ''}{a.due_at ? ` — ${formatUtc(a.due_at)}` : ''}{a.done ? ` (${tr('fait')})` : ''}</li>)}</ul></li>))}
            {crise.items.filter((a) => a.kind === 'action' && !a.parent_id).map((a) => <li key={a.id}>{a.body}{a.done ? ` (${tr('fait')})` : ''}</li>)}</ul>
          <h3>{tr('Registre des actions de gestion de crise')}</h3>
          <table className="grid"><thead><tr><th scope="col">{tr('Date')}</th><th scope="col">{tr('Type')}</th><th scope="col">{tr('Description')}</th><th scope="col">{tr('Arbitrage')}</th></tr></thead>
            <tbody>{crise.items.map((e) => <tr key={e.id}><td className="mono small">{formatUtc(e.created_at)}</td><td>{e.kind}</td><td>{e.body}{e.risque ? ` — ${tr('risque : {x}', { x: e.risque })}` : ''}</td><td>{e.entite || (e.decision_id ? crise.items.find((y) => y.id === e.decision_id)?.body : '') || '—'}</td></tr>)}</tbody></table>
          <h3>{tr('Critères de sortie de crise')}</h3>
          {crit('critere_sortie').length === 0 ? <p>{vide}</p> : <ul>{crit('critere_sortie').map((e) => <li key={e.id}>{e.body} — {e.done ? tr('atteint') : tr('non atteint')}</li>)}</ul>}
        </>}
        <h3>{tr("Retour d'expérience")}</h3>
        {s.rex_html ? <Html html={s.rex_html} /> : <p>{vide}</p>}
      </article>
    </>
  )
}
