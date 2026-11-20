import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, downloadBlob } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status } from '../components/Badges.jsx'
import { formatUtc } from '../labels.js'

const iso = (d) => d.toISOString().slice(0, 10)

export default function Reports() {
  const { me } = useAuth()
  const [qs] = useSearchParams()
  const today = new Date()
  const [f, setF] = useState({ client: qs.get('client') || me.clients[0]?.key || '', from: iso(new Date(today.getFullYear(), today.getMonth(), 1)), to: iso(today) })
  const [r, setR] = useState(null)
  const [error, setError] = useState('')
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const generate = async (e) => {
    e?.preventDefault(); setError('')
    try { setR(await api('/reports/period', { params: { client: f.client, from: f.from, to: f.to } })) } catch (x) { setError(x.message); setR(null) }
  }
  useEffect(() => { if (f.client) generate() }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const csv = async () => {
    try { downloadBlob(await api('/registre', { params: { client: f.client, from: f.from, to: f.to, format: 'csv' } }), `registre-${f.client}-${f.from}_${f.to}.csv`) } catch (x) { setError(x.message) }
  }
  return (
    <>
      <header className="page-head noprint"><div><h1>Rapports et registre</h1><p className="muted">Rapport périodique d'un client, exportable. Pour un PDF, utilisez « Imprimer » puis « Enregistrer au format PDF ».</p></div></header>
      <form className="filters noprint" onSubmit={generate} aria-label="Paramètres du rapport">
        <label className="filter">Client<select value={f.client} onChange={set('client')} required>{me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}</select></label>
        <label className="filter">Du<input type="date" value={f.from} onChange={set('from')} /></label>
        <label className="filter">Au<input type="date" value={f.to} onChange={set('to')} /></label>
        <div className="row gap" style={{ marginBottom: 10 }}>
          <button className="primary">Générer</button>
          <button type="button" onClick={csv}>Exporter le registre (CSV)</button>
          <button type="button" onClick={() => window.print()} disabled={!r}>Imprimer / PDF</button>
        </div>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      {r && (
        <article className="report card section" aria-label="Rapport périodique">
          <h1>Rapport d'incidents — {r.client.name}</h1>
          <p className="muted">Période du {r.period.from} au {r.period.to} · généré le {formatUtc(r.generated_at)} · TLP:AMBER</p>
          <h2>Synthèse</h2>
          <dl className="kv"><dt>Incidents créés</dt><dd>{r.totals.created}</dd><dt>Incidents clos</dt><dd>{r.totals.closed}</dd>
            <dt>Ouverts à ce jour</dt><dd>{r.totals.open}</dd><dt>Échéances tenues</dt><dd>{r.sla.rate_percent == null ? '—' : `${r.sla.rate_percent} % (${r.sla.resolution_within_target} sur ${r.sla.closed})`}</dd>
            <dt>Délai moyen de résolution</dt><dd>{r.delays.resolution_hours_avg == null ? '—' : `${r.delays.resolution_hours_avg} h`}</dd></dl>
          <h2>Incidents de la période</h2>
          <div className="table-wrap"><table className="grid">
            <thead><tr><th scope="col">Réf.</th><th scope="col">Titre</th><th scope="col">Détecté</th><th scope="col">Criticité</th><th scope="col">Gravité</th><th scope="col">Statut</th><th scope="col">MITRE</th></tr></thead>
            <tbody>
              {r.incidents.length === 0 && <tr><td colSpan="7" className="muted">Aucun incident sur la période.</td></tr>}
              {r.incidents.map((i) => <tr key={i.ref}><td className="mono">{i.ref}</td><td>{i.title}</td><td className="mono small">{formatUtc(i.detected_at)}</td><td><Severity value={i.criticite_initiale} /></td><td><Severity value={i.gravite} /></td><td><Status value={i.status} /></td><td className="mono small">{i.mitre.join(', ') || '—'}</td></tr>)}
            </tbody></table></div>
        </article>
      )}
    </>
  )
}
