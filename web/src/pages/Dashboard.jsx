import { t as tr } from '../i18n.js'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { BarList, TrendChart } from '../components/Charts.jsx'
import { STATUS } from '../labels.js'

const SEV_COLORS = { Critique: '#7A1020', 'Élevée': '#D9732A', Moyenne: '#C99A12', Faible: '#8D97A5' }
const fmtH = (h) => (h == null ? '—' : h < 48 ? `${h} h` : `${Math.round(h / 24 * 10) / 10} j`)
const iso = (d) => d.toISOString().slice(0, 10)

export default function Dashboard() {
  const { me } = useAuth()
  const today = new Date()
  const [f, setF] = useState({ client: '', from: iso(new Date(today.getTime() - 29 * 864e5)), to: iso(today) })
  const [d, setD] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    setError('')
    api('/dashboard', { params: { client: f.client || undefined, from: f.from, to: f.to } }).then(setD).catch((e) => { setError(e.message); setD(null) })
  }, [f])
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  return (
    <>
      <header className="page-head">
        <div><h1>{tr("Pilotage")}</h1><p className="muted">{tr("Charge de l'équipe, délais et respect des échéances sur la période choisie.")}</p></div>
        <Link to={`/rapports${f.client ? `?client=${f.client}` : ''}`} className="btn-link">{tr("Rapports et registre")}</Link>
      </header>
      <section className="filters" aria-label={tr("Période et client")}>
        {me.clients.length > 1 && <label className="filter">{tr("Client")}<select value={f.client} onChange={set('client')}><option value="">{tr("Tous")}</option>{me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}</select></label>}
        <label className="filter">{tr("Du")}<input type="date" value={f.from} onChange={set('from')} /></label>
        <label className="filter">{tr("Au")}<input type="date" value={f.to} onChange={set('to')} /></label>
      </section>
      {error && <p className="error" role="alert">{error}</p>}
      {!d && !error && <p className="loading">{tr("Chargement…")}</p>}
      {d && (
        <>
          <section className="stats" aria-label={tr("Indicateurs")}>
            <div className="card stat"><span className="muted">{tr("Créés")}</span><strong>{d.totals.created}</strong><span className="muted small">{tr("sur la période")}</span></div>
            <div className="card stat"><span className="muted">{tr("Clos")}</span><strong>{d.totals.closed}</strong><span className="muted small">{tr("sur la période")}</span></div>
            <div className="card stat"><span className="muted">{tr("Ouverts")}</span><strong>{d.totals.open}</strong><span className="muted small">{tr("à ce jour")}</span></div>
            <div className="card stat"><span className="muted">{tr("En retard")}</span><strong>{d.totals.overdue}</strong><span className="muted small">{tr("échéance dépassée")}</span></div>
            <div className="card stat"><span className="muted">{tr("Échéances tenues")}</span><strong>{d.sla.rate_percent == null ? '—' : `${d.sla.rate_percent} %`}</strong><span className="muted small">{d.sla.resolution_within_target} sur {d.sla.closed} clos</span></div>
          </section>
          <div className="grid2 dash">
            <section className="card section" aria-label={tr("Évolution")}><h2>{tr("Créés et clos par jour")}</h2><TrendChart data={d.trend} /></section>
            <section className="card section" aria-label={tr("Délais")}>
              <h2>{tr("Délais moyens")}</h2>
              <dl className="kv"><dt>{tr("Qualification")}</dt><dd>{fmtH(d.delays.qualification_hours_avg)} <span className="muted small">({d.delays.qualified_count} ticket(s))</span></dd>
                <dt>{tr("Résolution")}</dt><dd>{fmtH(d.delays.resolution_hours_avg)} <span className="muted small">({d.delays.closed_count} ticket(s))</span></dd></dl>
              <p className="muted small">Mesurés depuis la création du ticket. Les cibles se règlent par client (Administration &gt; Clients).</p>
            </section>
            <section className="card section" aria-label={tr("Tickets ouverts par gravité")}><h2>{tr("Ouverts par gravité")}</h2>
              <BarList label={tr("Tickets ouverts par gravité")} colors={SEV_COLORS} rows={Object.entries(d.open_by_severity).map(([label, value]) => ({ label, value, key: label }))} /></section>
            <section className="card section" aria-label={tr("Tickets par statut")}><h2>{tr("Tous les tickets par statut")}</h2>
              <BarList label={tr("Tickets par statut")} rows={Object.entries(STATUS).map(([k, v]) => ({ label: v.label, value: d.by_status[k] || 0 }))} /></section>
          </div>
          <section className="card section" aria-label={tr("Charge par analyste")}>
            <h2>{tr("Charge par analyste")}</h2>
            <div className="table-wrap"><table className="grid">
              <thead><tr><th scope="col">{tr("Analyste")}</th><th scope="col" className="num">{tr("Ouverts")}</th><th scope="col" className="num">{tr("En retard")}</th></tr></thead>
              <tbody>
                {d.workload.length === 0 && <tr><td colSpan="3" className="muted">{tr("Aucun ticket ouvert.")}</td></tr>}
                {d.workload.map((w) => <tr key={w.name}><td>{w.name}</td><td className="num">{w.open}</td><td className="num">{w.overdue ? <span className="pill danger">{w.overdue}</span> : 0}</td></tr>)}
              </tbody></table></div>
          </section>
        </>
      )}
    </>
  )
}
