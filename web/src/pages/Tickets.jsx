import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import { formatUtc, MITRE_SOURCE, STATUS } from '../labels.js'

const EMPTY = { status: '', client: '', rex_en_attente: false, q: '', assignee: '', overdue: false, sort: 'created', order: 'desc' }
const VIEWS = [['Tous', {}], ['Mes tickets', { assignee: 'me' }], ['Non assignés', { assignee: 'none' }], ['En retard', { overdue: true }]]

function SortHeader({ label, col, filters, set }) {
  const on = filters.sort === col
  const next = on && filters.order === 'desc' ? 'asc' : 'desc'
  return (
    <th scope="col" aria-sort={on ? (filters.order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="th-btn" onClick={() => set({ sort: col, order: next })}>{label}{on ? (filters.order === 'asc' ? ' ▲' : ' ▼') : ''}</button>
    </th>
  )
}

export default function Tickets() {
  const { me } = useAuth()
  const isClient = me.role === 'client'
  const [filters, setFilters] = useState(EMPTY)
  const [items, setItems] = useState(null)
  const [all, setAll] = useState(null) // synthèse : tous les statuts, indépendante des filtres
  const [total, setTotal] = useState(0)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState([])
  const [picked, setPicked] = useState(new Set())
  const [people, setPeople] = useState([])
  const [msg, setMsg] = useState('')
  const [draftQ, setDraftQ] = useState('')

  const params = useMemo(() => ({ ...filters, rex_en_attente: filters.rex_en_attente || undefined, overdue: filters.overdue || undefined, limit: 200 }), [filters])
  const reload = useCallback(() => {
    setError('')
    return api('/tickets', { params }).then((r) => { setItems(r.items); setTotal(r.total ?? r.items.length) }).catch((e) => setError(e.message))
  }, [params])
  useEffect(() => { reload() }, [reload])

  useEffect(() => {
    if (isClient) return undefined
    let alive = true
    api('/tickets', { params: { client: filters.client || undefined, limit: 500 } }).then((r) => alive && setAll(r)).catch(() => alive && setAll(null))
    return () => { alive = false }
  }, [filters.client, isClient, items])

  useEffect(() => {
    if (isClient) return
    api('/me/filters').then((r) => setSaved(r.items)).catch(() => {})
  }, [isClient])

  const set = (patch) => { setPicked(new Set()); setFilters((f) => ({ ...f, ...patch })) }
  const count = (fn) => (all?.items || []).filter(fn).length
  const stats = isClient ? [] : [
    ['À qualifier', count((t) => ['nouveau', 'en_evaluation'].includes(t.status)), 'nouveaux ou en évaluation'],
    ['En réponse', count((t) => t.status === 'en_reponse'), 'confinement / éradication'],
    ['Critiques ouverts', count((t) => (t.gravite || t.criticite_initiale) === 'Critique' && !['cloture', 'faux_positif', 'retour_experience'].includes(t.status)), 'gravité ou criticité'],
    ['En retard', count((t) => t.overdue), 'échéance dépassée'],
    ['REX en attente', count((t) => t.rex_en_attente), 'obligatoire si Élevée ou Critique'],
  ]
  const view = VIEWS.findIndex(([, p]) => (p.assignee || '') === filters.assignee && !!p.overdue === filters.overdue)

  const saveFilter = async () => {
    const name = window.prompt('Nom du filtre')
    if (!name) return
    const p = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== '' && v !== false))
    try { await api('/me/filters', { method: 'POST', json: { name, params: p } }); setSaved((await api('/me/filters')).items) } catch (e) { setError(e.message) }
  }
  const dropFilter = async (f) => { await api(`/me/filters/${f.id}`, { method: 'DELETE' }); setSaved(saved.filter((x) => x.id !== f.id)) }

  const toggle = (ref) => setPicked((s) => { const n = new Set(s); n.has(ref) ? n.delete(ref) : n.add(ref); return n })
  const bulkAssign = async (username) => {
    try {
      const r = await api('/tickets/bulk-assign', { method: 'POST', json: { refs: [...picked], username: username || null } })
      setMsg(`${r.done} ticket(s) affecté(s)${r.done < r.results.length ? `, ${r.results.length - r.done} refusé(s)` : ''}.`)
      setPicked(new Set()); reload()
    } catch (e) { setError(e.message) }
  }
  useEffect(() => { if (picked.size && !people.length) api('/tickets/' + encodeURIComponent([...picked][0]) + '/assignables').then((r) => setPeople(r.items)).catch(() => {}) }, [picked, people.length])

  const cols = isClient ? 9 : 11
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

      {!isClient && (
        <div className="row wrap gap views" role="group" aria-label="Vues">
          {VIEWS.map(([label, p], i) => (
            <button type="button" key={label} className={`vchip${view === i ? ' on' : ''}`} aria-pressed={view === i}
              onClick={() => set({ assignee: p.assignee || '', overdue: !!p.overdue })}>{label}</button>
          ))}
          {saved.length > 0 && <span className="muted small">Filtres :</span>}
          {saved.map((f) => (
            <span key={f.id} className="vchip saved">
              <button type="button" className="link" onClick={() => set({ ...EMPTY, ...f.params })}>{f.name}</button>
              <button type="button" className="x" aria-label={`Supprimer le filtre ${f.name}`} onClick={() => dropFilter(f)}>×</button>
            </span>
          ))}
        </div>
      )}

      <section className="filters" aria-label="Filtres">
        <form className="filter grow" role="search" onSubmit={(e) => { e.preventDefault(); set({ q: draftQ }) }}>
          <label>Recherche
            <input type="search" value={draftQ} onChange={(e) => setDraftQ(e.target.value)} placeholder="Titre, règle, agent, IP, commentaire…" />
          </label>
        </form>
        <label className="filter">Statut
          <select value={filters.status} onChange={(e) => set({ status: e.target.value })}>
            <option value="">Tous</option>
            {Object.entries(STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </label>
        {me.clients.length > 1 && (
          <label className="filter">Client
            <select value={filters.client} onChange={(e) => set({ client: e.target.value })}>
              <option value="">Tous</option>
              {me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}
            </select>
          </label>
        )}
        {!isClient && (
          <label className="filter check">
            <input type="checkbox" checked={filters.rex_en_attente} onChange={(e) => set({ rex_en_attente: e.target.checked })} />
            REX en attente
          </label>
        )}
        <div className="row gap" style={{ marginBottom: 10 }}>
          <button type="button" onClick={() => { setDraftQ(''); set(EMPTY) }}>Réinitialiser</button>
          {!isClient && <button type="button" onClick={saveFilter}>Enregistrer ce filtre</button>}
        </div>
      </section>

      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {items && total > items.length && <p className="muted small" role="status">{items.length} tickets affichés sur {total} : affinez avec les filtres.</p>}
      {all && !isClient && (all.total ?? 0) > all.items.length && <p className="muted small" role="status">Synthèse calculée sur les {all.items.length} tickets les plus récents (sur {all.total}).</p>}

      {picked.size > 0 && (
        <div className="bulkbar card" role="region" aria-label="Actions groupées">
          <strong>{picked.size} sélectionné(s)</strong>
          <label className="check">Affecter à
            <select defaultValue="" onChange={(e) => { if (e.target.value !== '') bulkAssign(e.target.value === '__none' ? null : e.target.value); e.target.value = '' }}>
              <option value="" disabled>Choisir…</option>
              <option value="__none">Personne</option>
              {people.map((p) => <option key={p.username} value={p.username}>{p.display_name}</option>)}
            </select>
          </label>
          <button type="button" onClick={() => setPicked(new Set())}>Désélectionner</button>
        </div>
      )}

      <div className="table-wrap card">
        <table className="grid">
          <thead>
            <tr>
              {!isClient && <th scope="col"><span className="sr-only">Sélection</span></th>}
              <SortHeader label="Réf." col="ref" filters={filters} set={set} /><th scope="col">Titre</th>
              {me.clients.length > 1 && <th scope="col">Client</th>}
              <th scope="col">Criticité</th><th scope="col">Gravité</th><SortHeader label="Statut" col="status" filters={filters} set={set} />
              <th scope="col">MITRE ATT&amp;CK</th>
              {!isClient && <th scope="col">Assigné</th>}
              <SortHeader label="Détecté" col="detected" filters={filters} set={set} /><th scope="col">TLP</th>
              <SortHeader label="Occur." col="occurrences" filters={filters} set={set} />
            </tr>
          </thead>
          <tbody>
            {items === null && <tr><td colSpan={cols + 1} className="muted">Chargement…</td></tr>}
            {items?.length === 0 && <tr><td colSpan={cols + 1} className="muted">Aucun ticket ne correspond.</td></tr>}
            {items?.map((t) => (
              <tr key={t.ref} className={t.overdue ? 'overdue' : ''}>
                {!isClient && <td><input type="checkbox" aria-label={`Sélectionner ${t.ref}`} checked={picked.has(t.ref)} onChange={() => toggle(t.ref)} /></td>}
                <td className="mono"><Link to={`/tickets/${encodeURIComponent(t.ref)}`}>{t.ref}</Link></td>
                <td className="strong">{t.title}{t.overdue && <span className="pill danger" style={{ marginLeft: 8 }}>En retard</span>}{t.crisis && <span className="pill danger" style={{ marginLeft: 8 }}>CRISE</span>}</td>
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
