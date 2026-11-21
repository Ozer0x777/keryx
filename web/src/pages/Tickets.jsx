import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import { t as tr } from '../i18n.js'
import { formatUtc, MITRE_SOURCE, STATUS } from '../labels.js'

const EMPTY = { status: '', client: '', rex_en_attente: false, q: '', assignee: '', overdue: false, sort: 'created', order: 'desc' }
// Libellés sources (français) : traduits à l'affichage par tr(label).
const VIEWS = [['Tous', {}], ['Mes tickets', { assignee: 'me' }], ['Non assignés', { assignee: 'none' }], ['En retard', { overdue: true }]]

function SortHeader({ label, col, filters, set }) {
  const on = filters.sort === col
  const next = on && filters.order === 'desc' ? 'asc' : 'desc'
  return (
    <th scope="col" aria-sort={on ? (filters.order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="th-btn" onClick={() => set({ sort: col, order: next })}>{tr(label)}{on ? (filters.order === 'asc' ? ' ▲' : ' ▼') : ''}</button>
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
    [tr('À qualifier'), count((t) => ['nouveau', 'en_evaluation'].includes(t.status)), tr('nouveaux ou en évaluation')],
    [tr('En réponse'), count((t) => t.status === 'en_reponse'), tr('confinement / éradication')],
    [tr('Critiques ouverts'), count((t) => (t.gravite || t.criticite_initiale) === 'Critique' && !['cloture', 'faux_positif', 'retour_experience'].includes(t.status)), tr('gravité ou criticité')],
    [tr('En retard'), count((t) => t.overdue), tr('échéance dépassée')],
    [tr('REX en attente'), count((t) => t.rex_en_attente), tr('obligatoire si Élevée ou Critique')],
  ]
  const view = VIEWS.findIndex(([, p]) => (p.assignee || '') === filters.assignee && !!p.overdue === filters.overdue)

  const saveFilter = async () => {
    const name = window.prompt(tr('Nom du filtre'))
    if (!name) return
    const p = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== '' && v !== false))
    try { await api('/me/filters', { method: 'POST', json: { name, params: p } }); setSaved((await api('/me/filters')).items) } catch (e) { setError(e.message) }
  }
  const dropFilter = async (f) => { await api(`/me/filters/${f.id}`, { method: 'DELETE' }); setSaved(saved.filter((x) => x.id !== f.id)) }

  const toggle = (ref) => setPicked((s) => { const n = new Set(s); n.has(ref) ? n.delete(ref) : n.add(ref); return n })
  const bulkAssign = async (username) => {
    try {
      const r = await api('/tickets/bulk-assign', { method: 'POST', json: { refs: [...picked], username: username || null } })
      setMsg(r.done < r.results.length
        ? tr('{n} ticket(s) affecté(s), {k} refusé(s).', { n: r.done, k: r.results.length - r.done })
        : tr('{n} ticket(s) affecté(s).', { n: r.done }))
      setPicked(new Set()); reload()
    } catch (e) { setError(e.message) }
  }
  useEffect(() => { if (picked.size && !people.length) api('/tickets/' + encodeURIComponent([...picked][0]) + '/assignables').then((r) => setPeople(r.items)).catch(() => {}) }, [picked, people.length])

  const cols = isClient ? 9 : 11
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{isClient ? tr('Mes incidents') : tr('File des tickets')}</h1>
          <p className="muted">{isClient
            ? tr('Vous voyez uniquement les tickets de votre organisation et les échanges qui vous sont destinés.')
            : tr('Clients affectés : {clients}', { clients: me.clients.map((c) => c.name).join(', ') || tr('aucun') })}</p>
        </div>
        {!isClient && (
          <div className="segmented" role="group" aria-label={tr('Type de vue')}>
            <Link to="/tickets" className="on" aria-current="page">{tr('Liste')}</Link>
            <Link to="/kanban">{tr("Kanban")}</Link>
          </div>
        )}
      </header>

      {!isClient && (
        <section className="stats" aria-label={tr('Synthèse')}>
          {stats.map(([label, value, hint]) => (
            <div className="card stat" key={label}>
              <span className="muted">{label}</span><strong>{all ? value : '…'}</strong><span className="muted small">{hint}</span>
            </div>
          ))}
        </section>
      )}

      {!isClient && (
        <div className="row wrap gap views" role="group" aria-label={tr('Vues')}>
          {VIEWS.map(([label, p], i) => (
            <button type="button" key={label} className={`vchip${view === i ? ' on' : ''}`} aria-pressed={view === i}
              onClick={() => set({ assignee: p.assignee || '', overdue: !!p.overdue })}>{tr(label)}</button>
          ))}
          {saved.length > 0 && <span className="muted small">{tr('Filtres :')}</span>}
          {saved.map((f) => (
            <span key={f.id} className="vchip saved">
              {/* Le champ de recherche suit le filtre appliqué (sinon il garde l'ancienne saisie et la renvoie au prochain Entrée). */}
              <button type="button" className="link" onClick={() => { setDraftQ(f.params?.q || ''); set({ ...EMPTY, ...f.params }) }}>{f.name}</button>
              <button type="button" className="x" aria-label={tr('Supprimer le filtre {name}', { name: f.name })} onClick={() => dropFilter(f)}>×</button>
            </span>
          ))}
        </div>
      )}

      <section className="filters" aria-label={tr('Filtres')}>
        <form className="filter grow" role="search" onSubmit={(e) => { e.preventDefault(); set({ q: draftQ }) }}>
          <label>{tr('Recherche')}
            <input type="search" value={draftQ} onChange={(e) => setDraftQ(e.target.value)} placeholder={tr('Titre, règle, agent, IP, commentaire…')} />
          </label>
        </form>
        <label className="filter">{tr('Statut')}
          <select value={filters.status} onChange={(e) => set({ status: e.target.value })}>
            <option value="">{tr('Tous')}</option>
            {Object.entries(STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </label>
        {me.clients.length > 1 && (
          <label className="filter">{tr('Client')}
            <select value={filters.client} onChange={(e) => set({ client: e.target.value })}>
              <option value="">{tr("Tous")}</option>
              {me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}
            </select>
          </label>
        )}
        {!isClient && (
          <label className="filter check">
            <input type="checkbox" checked={filters.rex_en_attente} onChange={(e) => set({ rex_en_attente: e.target.checked })} />
            {tr('REX en attente')}
          </label>
        )}
        <div className="row gap">
          <button type="button" onClick={() => { setDraftQ(''); set(EMPTY) }}>{tr('Réinitialiser')}</button>
          {!isClient && <button type="button" onClick={saveFilter}>{tr('Enregistrer ce filtre')}</button>}
        </div>
      </section>

      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {items && total > items.length && <p className="muted small" role="status">{tr('{n} tickets affichés sur {total} : affinez avec les filtres.', { n: items.length, total })}</p>}
      {all && !isClient && (all.total ?? 0) > all.items.length && <p className="muted small" role="status">{tr('Synthèse calculée sur les {n} tickets les plus récents (sur {total}).', { n: all.items.length, total: all.total })}</p>}

      {picked.size > 0 && (
        <div className="bulkbar card" role="region" aria-label={tr('Actions groupées')}>
          <strong>{picked.size} {tr('sélectionné(s)')}</strong>
          <label className="check">{tr('Affecter à')}
            <select defaultValue="" onChange={(e) => { if (e.target.value !== '') bulkAssign(e.target.value === '__none' ? null : e.target.value); e.target.value = '' }}>
              <option value="" disabled>{tr('Choisir…')}</option>
              <option value="__none">{tr('Personne')}</option>
              {people.map((p) => <option key={p.username} value={p.username}>{p.display_name}</option>)}
            </select>
          </label>
          <button type="button" onClick={() => setPicked(new Set())}>{tr('Désélectionner')}</button>
        </div>
      )}

      <div className="table-wrap card">
        <table className="grid">
          <thead>
            <tr>
              {!isClient && <th scope="col"><span className="sr-only">{tr("Sélection")}</span></th>}
              <SortHeader label={tr('Réf.')} col="ref" filters={filters} set={set} /><th scope="col">{tr('Titre')}</th>
              {me.clients.length > 1 && <th scope="col">{tr('Client')}</th>}
              <th scope="col">{tr('Criticité')}</th><th scope="col">{tr('Gravité')}</th><SortHeader label={tr('Statut')} col="status" filters={filters} set={set} />
              <th scope="col">MITRE ATT&amp;CK</th>
              {!isClient && <th scope="col">{tr('Assigné')}</th>}
              <SortHeader label={tr('Détecté')} col="detected" filters={filters} set={set} /><th scope="col">{tr("TLP")}</th>
              <SortHeader label={tr('Occur.')} col="occurrences" filters={filters} set={set} />
            </tr>
          </thead>
          <tbody>
            {items === null && <tr><td colSpan={cols + 1} className="muted">{tr('Chargement…')}</td></tr>}
            {items?.length === 0 && <tr><td colSpan={cols + 1} className="muted">{tr('Aucun ticket ne correspond.')}</td></tr>}
            {items?.map((t) => (
              <tr key={t.ref} className={t.overdue ? 'overdue' : ''}>
                {!isClient && <td><input type="checkbox" aria-label={tr('Sélectionner {ref}', { ref: t.ref })} checked={picked.has(t.ref)} onChange={() => toggle(t.ref)} /></td>}
                <td className="mono"><Link to={`/tickets/${encodeURIComponent(t.ref)}`}>{t.ref}</Link></td>
                <td className="strong title-cell">{t.title}{t.overdue && <span className="pill danger" style={{ marginLeft: 8 }}>{tr('En retard')}</span>}{t.crisis && <span className="pill danger" style={{ marginLeft: 8 }}>{tr("CRISE")}</span>}</td>
                {me.clients.length > 1 && <td className="mono small" title={t.client}>{t.client_key}</td>}
                <td><Severity value={t.criticite_initiale} /></td>
                <td><Severity value={t.gravite} /></td>
                <td><Status value={t.status} />{t.rex_en_attente && <span className="pill warn">{tr("REX")}</span>}</td>
                <td title={`${tr('Source')} : ${MITRE_SOURCE[t.mitre_source]}`}><span className="mono">{t.mitre.join(', ') || '—'}</span></td>
                {!isClient && <td>{t.assignee || '—'}</td>}
                <td className="mono small">{formatUtc(t.detected_at)}</td>
                <td><Tlp value={t.tlp} /></td>
                <td className="num mono">{t.occurrences}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">{tr('Criticité initiale calculée depuis le niveau de règle Wazuh · gravité fixée à la qualification.')}</p>
    </>
  )
}
