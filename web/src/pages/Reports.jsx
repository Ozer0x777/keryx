import { AcquittementTable } from '../components/Acquittement.jsx'
import { t as tr } from '../i18n.js'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import ParcSummary from '../components/ParcSummary.jsx'
import { api, downloadBlob } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status } from '../components/Badges.jsx'
import { formatUtc } from '../labels.js'
import { isoDay, monthStartUtc } from '../dates.js'

export default function Reports() {
  const { me } = useAuth()
  const [qs] = useSearchParams()
  const today = new Date()
  const [f, setF] = useState({ client: qs.get('client') || me.clients[0]?.key || '', from: monthStartUtc(today), to: isoDay(today) })
  const [r, setR] = useState(null)
  const [error, setError] = useState('')
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const generate = async (e) => {
    e?.preventDefault(); setError('')
    try { setR(await api('/reports/period', { params: { client: f.client, from: f.from, to: f.to } })) } catch (x) { setError(x.message); setR(null) }
  }
  useEffect(() => { if (f.client) generate() }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const notifCsv = async () => {
    try { downloadBlob(await api('/registre-notifications', { params: { client: f.client, from: f.from, to: f.to, format: 'csv' } }), `notifications-${f.client}-${f.from}_${f.to}.csv`) } catch (x) { setError(x.message) }
  }
  const csv = async () => {
    try { downloadBlob(await api('/registre', { params: { client: f.client, from: f.from, to: f.to, format: 'csv' } }), `registre-${f.client}-${f.from}_${f.to}.csv`) } catch (x) { setError(x.message) }
  }
  return (
    <>
      <header className="page-head noprint"><div><h1>{tr("Rapports et registre")}</h1><p className="muted">{tr("Rapport périodique d'un client, exportable. Pour un PDF, utilisez « Imprimer » puis « Enregistrer au format PDF ».")}</p></div></header>
      <form className="filters noprint" onSubmit={generate} aria-label={tr("Paramètres du rapport")}>
        <label className="filter">{tr("Client")}<select value={f.client} onChange={set('client')} required>{me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}</select></label>
        <label className="filter">{tr("Du")}<input type="date" value={f.from} onChange={set('from')} /></label>
        <label className="filter">{tr("Au")}<input type="date" value={f.to} onChange={set('to')} /></label>
        <div className="row wrap gap">
          <button className="primary">{tr("Générer")}</button>
          <button type="button" onClick={csv}>{tr("Exporter le registre (CSV)")}</button>
          <button type="button" onClick={notifCsv}>{tr("Exporter le registre des notifications (CSV)")}</button>
          <button type="button" onClick={() => window.print()} disabled={!r}>{tr("Imprimer / PDF")}</button>
        </div>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      {r && (
        <article className="report card section" aria-label={tr("Rapport périodique")}>
          <h1>{tr("Rapport d'incidents")} — {r.client.name}</h1>
          <p className="muted">{tr('Période du {from} au {to} · généré le {when} · TLP:AMBER', { from: r.period.from, to: r.period.to, when: formatUtc(r.generated_at) })}</p>
          <h2>{tr("Synthèse")}</h2>
          <dl className="kv"><dt>{tr("Incidents créés")}</dt><dd>{r.totals.created}</dd><dt>{tr("Incidents clos")}</dt><dd>{r.totals.closed}</dd>
            <dt>{tr("Ouverts à ce jour")}</dt><dd>{r.totals.open}</dd><dt>{tr("Échéances tenues")}</dt><dd>{r.sla.rate_percent == null ? '—' : tr('{p} % ({a} sur {b})', { p: r.sla.rate_percent, a: r.sla.resolution_within_target, b: r.sla.closed })}</dd>
            <dt>{tr("Délai moyen de résolution")}</dt><dd>{r.delays.resolution_hours_avg == null ? '—' : `${r.delays.resolution_hours_avg} h`}</dd></dl>
          {r.acquittement && <>
            <h2>{tr("Délai d'acquittement")}</h2>
            <p className="muted small">{tr("De la détection à la première action de l'équipe, par criticité.")}</p>
            <AcquittementTable data={r.acquittement} caption={tr("Délai d'acquittement par criticité")} />
          </>}
          <h2>{tr("Incidents de la période")}</h2>
          <div className="table-wrap"><table className="grid">
            <thead><tr><th scope="col">{tr("Réf.")}</th><th scope="col">{tr("Titre")}</th><th scope="col">{tr("Détecté")}</th><th scope="col">{tr("Criticité")}</th><th scope="col">{tr("Gravité")}</th><th scope="col">{tr("Statut")}</th><th scope="col">{tr("MITRE")}</th></tr></thead>
            <tbody>
              {r.incidents.length === 0 && <tr><td colSpan="7" className="muted">{tr("Aucun incident sur la période.")}</td></tr>}
              {r.incidents.map((i) => <tr key={i.ref}><td className="mono">{i.ref}</td><td>{i.title}</td><td className="mono small">{formatUtc(i.detected_at)}</td><td><Severity value={i.criticite_initiale} /></td><td><Severity value={i.gravite} /></td><td><Status value={i.status} /></td><td className="mono small">{i.mitre.join(', ') || '—'}</td></tr>)}
            </tbody></table></div>
          <ParcSummary parc={r.parc} links={false} />
        </article>
      )}
    </>
  )
}
