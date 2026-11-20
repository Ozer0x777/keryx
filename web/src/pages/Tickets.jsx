import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import { formatUtc, MITRE_SOURCE, STATUS } from '../labels.js'

export default function Tickets() {
  const { me } = useAuth()
  const [filters, setFilters] = useState({ status: '', client: '', rex_en_attente: false })
  const [items, setItems] = useState(null)
  const [all, setAll] = useState(null) // synthèse : tous les statuts, indépendante du filtre de statut
  const [total, setTotal] = useState(0)
  const [error, setError] = useState('')
  const isClient = me.role === 'client'

  useEffect(() => {
    let alive = true
    setError('')
    api('/tickets', { params: { ...filters, rex_en_attente: filters.rex_en_attente || undefined, limit: 200 } })
      .then((r) => { if (alive) { setItems(r.items); setTotal(r.total ?? r.items.length) } })
      .catch((e) => alive && setError(e.message))
    return () => { alive = false }
  }, [filters])

  useEffect(() => {
    if (isClient) return undefined
    let alive = true
    api('/tickets', { params: { client: filters.client || undefined, limit: 500 } })
      .then((r) => alive && setAll(r))
      .catch(() => alive && setAll(null))
    return () => { alive = false }
  }, [filters.client, isClient])

  const count = (fn) => (all?.items || []).filter(fn).length
  const stats = isClient ? [] : [
    ['À qualifier', count((t) => ['nouveau', 'en_evaluation'].includes(t.status)), 'nouveaux ou en évaluation'],
    ['En réponse', count((t) => t.status === 'en_reponse'), 'confinement / éradication'],
    ['Critiques ouverts', count((t) => (t.gravite || t.criticite_initiale) === 'Critique' && !['cloture', 'faux_positif', 'retour_experience'].includes(t.status)), 'gravité ou criticité'],
    ['REX en attente', count((t) => t.rex_en_attente), 'obligatoire si Élevée ou Critique'],
  ]
  const set = (k, v) => setFilters((f) => ({ ...f, [k]: v }))

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{isClient ? 'Mes incidents' : 'File des tickets'}</h1>
          <p className="muted">{isClient
            ? 'Vous voyez uniquement les tickets de votre organisation et les échanges qui vous sont destinés.'
            : `Clients affectés : ${me.clients.map((c) => c.name).join(', ') || 'aucun'}`}</p>
        </div>
        {!isClient && (
          <div className="segmented" role="group" aria-label="Type de vue">
            <Link to="/tickets" className="on" aria-current="page">Liste</Link>
            <Link to="/kanban">Kanban</Link>
          </div>
        )}
      </header>

      {!isClient && (
        <section className="stats" aria-label="Synthèse">
          {stats.map(([label, value, hint]) => (
            <div className="card stat" key={label}>
              <span className="muted">{label}</span><strong>{all ? value : '…'}</strong><span className="muted small">{hint}</span>
            </div>
          ))}
        </section>
      )}

      <section className="filters" aria-label="Filtres">
        <label className="filter">Statut
          <select value={filters.status} onChange={(e) => set('status', e.target.value)}>
            <option value="">Tous</option>
            {Object.entries(STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </label>
        {me.clients.length > 1 && (
          <label className="filter">Client
            <select value={filters.client} onChange={(e) => set('client', e.target.value)}>
              <option value="">Tous</option>
              {me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}
            </select>
          </label>
        )}
        {!isClient && (
          <label className="filter check">
            <input type="checkbox" checked={filters.rex_en_attente} onChange={(e) => set('rex_en_attente', e.target.checked)} />
            REX en attente
          </label>
        )}
      </section>

      {error && <p className="error" role="alert">{error}</p>}
      {items && total > items.length && (
        <p className="muted small" role="status">{items.length} tickets affichés sur {total} : affinez avec les filtres.</p>
      )}
      {all && !isClient && (all.total ?? 0) > all.items.length && (
        <p className="muted small" role="status">Synthèse calculée sur les {all.items.length} tickets les plus récents (sur {all.total}).</p>
      )}
      <div className="table-wrap card">
        <table className="grid">
          <thead>
            <tr>
              <th scope="col">Réf.</th><th scope="col">Titre</th>
              {me.clients.length > 1 && <th scope="col">Client</th>}
              <th scope="col">Criticité</th><th scope="col">Gravité</th><th scope="col">Statut</th>
              <th scope="col">MITRE ATT&amp;CK</th>
              {!isClient && <th scope="col">Assigné</th>}
              <th scope="col">Détecté</th><th scope="col">TLP</th><th scope="col" className="num">Occur.</th>
            </tr>
          </thead>
          <tbody>
            {items === null && <tr><td colSpan="11" className="muted">Chargement…</td></tr>}
            {items?.length === 0 && <tr><td colSpan="11" className="muted">Aucun ticket.</td></tr>}
            {items?.map((t) => (
              <tr key={t.ref}>
                <td className="mono"><Link to={`/tickets/${encodeURIComponent(t.ref)}`}>{t.ref}</Link></td>
                <td className="strong">{t.title}</td>
                {me.clients.length > 1 && <td>{t.client}</td>}
                <td><Severity value={t.criticite_initiale} /></td>
                <td><Severity value={t.gravite} /></td>
                <td><Status value={t.status} />{t.rex_en_attente && <span className="pill warn">REX</span>}</td>
                <td><span className="mono">{t.mitre.join(', ') || '—'}</span> <span className="muted small">({MITRE_SOURCE[t.mitre_source]})</span></td>
                {!isClient && <td>{t.assignee || '—'}</td>}
                <td className="mono small">{formatUtc(t.detected_at)}</td>
                <td><Tlp value={t.tlp} /></td>
                <td className="num mono">{t.occurrences}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">Criticité initiale calculée depuis le niveau de règle Wazuh · gravité fixée à la qualification.</p>
    </>
  )
}
