import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import PdfButton from '../components/PdfButton.jsx'
import { DISCRETION, ETATS_MESURE, MENACE, PRESENCE } from '../components/Pris.jsx'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'

// Point de situation, ou restitution « à chaud » (PRIS VI.6.a, VI.5.3.a) : ce qui s'est passé sur le ticket depuis
// une durée choisie, et l'état de la compréhension et des mesures, imprimable pour le correspondant du commanditaire.
export default function PointSituation() {
  const { ref } = useParams()
  const enc = encodeURIComponent(ref)
  const [heures, setHeures] = useState(24)
  const [p, setP] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { setP(null); api(`/tickets/${enc}/point-situation`, { params: { heures } }).then(setP).catch((e) => setError(e.message)) }, [enc, heures])
  if (error) return <p className="error" role="alert">{error}</p>
  return (
    <>
      <div className="row wrap gap noprint" style={{ marginBottom: 12 }}>
        <Link to={`/tickets/${enc}`}>{tr('← Retour au ticket')}</Link>
        <label>{tr('Depuis')}<select value={heures} onChange={(e) => setHeures(Number(e.target.value))}>
          <option value={24}>{tr('24 heures')}</option><option value={72}>{tr('3 jours')}</option><option value={168}>{tr('7 jours')}</option></select></label>
        <PdfButton path={`/tickets/${enc}/point-situation.pdf`} params={{ heures }} filename={`${ref}-point-de-situation.pdf`} />
        <button type="button" onClick={() => window.print()}>{tr('Imprimer')}</button>
      </div>
      {!p ? <p className="loading">{tr('Chargement…')}</p> : (
        <article className="report card section" aria-label={tr('Point de situation')}>
          <h1>{tr('Point de situation')} — {p.ref}</h1>
          <p className="muted">{p.titre} · {tr('du {a} au {b}', { a: formatUtc(p.depuis), b: formatUtc(p.genere_le) })}</p>
          <h2>{tr("Compréhension de l'incident")}</h2>
          <dl className="kv">
            <dt>{tr("L'attaquant est-il toujours présent ?")}</dt><dd>{PRESENCE[p.comprehension.attaquant_present] || '—'}</dd>
            <dt>{tr('Niveau de menace estimé')}</dt><dd>{MENACE[p.comprehension.niveau_menace] || '—'}</dd>
            <dt>{tr("Niveau de discrétion vis-à-vis de l'attaquant")}</dt><dd>{DISCRETION[p.posture.discretion] || '—'}</dd>
          </dl>
          <h2>{tr("Mesures d'endiguement")}</h2>
          {p.mesures.length === 0 ? <p className="muted">{tr('Aucune mesure proposée.')}</p>
            : <ul>{p.mesures.map((m) => <li key={m.id}>{m.libelle} — {ETATS_MESURE[m.etat]}</li>)}</ul>}
          <h2>{tr('Activité de la période')}</h2>
          {p.actions.length === 0 ? <p className="muted">{tr('Aucune action sur la période.')}</p> : (
            <table className="grid"><thead><tr><th scope="col">{tr('Date')}</th><th scope="col">{tr('Auteur')}</th><th scope="col">{tr('Action')}</th></tr></thead>
              <tbody>{p.actions.map((a, i) => <tr key={i}><td className="mono small">{formatUtc(a.ts)}</td><td>{a.acteur}</td><td>{a.action}</td></tr>)}</tbody></table>)}
          {p.actions_omises > 0 && <p className="muted">{tr('{n} action(s) plus ancienne(s) de la période non reprise(s) ici : voir le registre du ticket.', { n: p.actions_omises })}</p>}
          <p>{tr('{o} occurrence(s) de l\'alerte, {n} commentaire(s), {m} pièce(s) collectée(s), {c} entrée(s) de crise sur la période.', { o: p.occurrences, n: p.commentaires.length, m: p.pieces.length, c: p.crise.length })}</p>
          {p.crise.length > 0 && <><h2>{tr('Crise')}</h2><ul>{p.crise.map((e, i) => <li key={i}>{formatUtc(e.ts)} — {e.type} : {e.texte}</li>)}</ul></>}
        </article>
      )}
    </>
  )
}
