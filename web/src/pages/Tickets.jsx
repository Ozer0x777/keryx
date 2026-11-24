import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import { utcClock } from '../dates.js'
import { t as tr } from '../i18n.js'
import { MITRE_SOURCE, STATUS } from '../labels.js'
import {
  cardActive, cardPatch, DEFAULTS, filtersFromSearch, filtersToSearch, OPEN_STATUSES, rememberQueue, SEVERITIES, TO_QUALIFY,
} from '../queue.js'

const REFRESH_MS = 45000
// Libellés sources (français) : traduits à l'affichage par tr(label).
const VIEWS = [['Tous', ''], ['Mes tickets', 'me'], ['Non assignés', 'none']]
// Cartes de chiffres : chacune est un filtre rapide (voir queue.js) et affiche le nombre de tickets qu'elle listerait.
// Les nombres viennent du point d'API de comptage (/tickets/counts), calculés par le serveur sur tous les tickets
// visibles : le relevé de la file ne recharge plus 500 tickets pour les compter.
const CARDS = [
  { label: 'À qualifier', hint: 'nouveaux ou en évaluation', patch: { status: TO_QUALIFY }, count: (c) => c.by_status.nouveau + c.by_status.en_evaluation },
  { label: 'En réponse', hint: 'confinement / éradication', patch: { status: 'en_reponse' }, count: (c) => c.by_status.en_reponse },
  { label: 'Critiques ouverts', hint: 'gravité ou criticité', patch: { status: OPEN_STATUSES, severity: 'Critique' }, count: (c) => c.open_by_severity.Critique },
  { label: 'En retard', hint: 'échéance dépassée', patch: { overdue: true }, count: (c) => c.overdue },
  { label: 'REX en attente', hint: 'obligatoire si Élevée ou Critique', patch: { rex_en_attente: true }, count: (c) => c.rex_en_attente },
]
// Vues de priorisation (ADR-0025) : ce qui demande une action de l'équipe. Chacune fixe aussi l'assigné, pour ne pas
// garder à l'insu de l'analyste la vue « Mes tickets » ou « Non assignés » d'une autre carte.
const PRIORITIES = [
  { label: 'Critiques non assignés', hint: 'ouverts, personne dessus', patch: { status: OPEN_STATUSES, severity: 'Critique', assignee: 'none' }, count: (c) => c.critical_unassigned },
  { label: 'En attente du client', hint: 'sa réponse n\'est pas arrivée', patch: { awaiting_client: true, assignee: '' }, count: (c) => c.awaiting_client },
  { label: 'Dossiers incomplets', hint: 'gravité, assigné ou synthèse manquants', patch: { incomplete: true, assignee: '' }, count: (c) => c.incomplete },
]

// Date de détection sans le suffixe « UTC » (il est dans l'en-tête de colonne) : la colonne reste étroite.
const utcShort = (iso) => (iso ? iso.replace('T', ' ').slice(0, 16) : '—')

function SortHeader({ label, col, filters, set, className }) {
  const on = filters.sort === col
  const next = on && filters.order === 'desc' ? 'asc' : 'desc'
  return (
    <th scope="col" className={className} aria-sort={on ? (filters.order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className={`th-btn${on ? ' on' : ''}`} onClick={() => set({ sort: col, order: next })}>
        {label}<span className="sort-mark" aria-hidden="true">{on ? (filters.order === 'asc' ? '▲' : '▼') : ''}</span>
      </button>
    </th>
  )
}

// Carte de chiffre = filtre rapide : enfoncée quand ses critères sont appliqués, un second clic les retire.
function StatCard({ c, counts, filters, set }) {
  const on = cardActive(filters, c.patch)
  return (
    <button type="button" className={`card stat stat-filter${on ? ' on' : ''}`} aria-pressed={on}
      onClick={() => set(cardPatch(on ? {} : c.patch))}>
      <span className="stat-label">{tr(c.label)}</span>
      <strong>{counts ? c.count(counts) : '…'}</strong>
      <span className="stat-hint small">{on ? tr('filtre actif') : tr(c.hint)}</span>
    </button>
  )
}

export default function Tickets() {
  const { me } = useAuth()
  const isClient = me.role === 'client'
  const [search, setSearch] = useSearchParams()
  const filters = useMemo(() => filtersFromSearch(search), [search])
  const [items, setItems] = useState(null)
  const [counts, setCounts] = useState(null) // synthèse : compteurs de tous les tickets visibles, indépendants des filtres
  const [total, setTotal] = useState(0)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState([])
  const [picked, setPicked] = useState(new Set())
  const [people, setPeople] = useState([])
  const [msg, setMsg] = useState('')
  const [draftQ, setDraftQ] = useState(filters.q)
  const [updatedAt, setUpdatedAt] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [ask, dialog] = useConfirm()
  const selectAll = useRef(null)
  const request = useRef(0)
  const lastLoad = useRef(0)

  // L'URL est la source de vérité : au retour d'un ticket (bouton Précédent ou fil d'Ariane), la file retrouve ses
  // filtres, son tri et sa vue. Le champ de recherche suit l'URL (sinon il garderait l'ancienne saisie).
  useEffect(() => { setDraftQ(filters.q) }, [filters.q])
  useEffect(() => { rememberQueue(search.toString()) }, [search])

  const key = search.toString()
  const params = useMemo(() => {
    const f = filtersFromSearch(key)
    return { ...f, rex_en_attente: f.rex_en_attente || undefined, overdue: f.overdue || undefined,
      awaiting_client: f.awaiting_client || undefined, incomplete: f.incomplete || undefined, limit: 200 }
  }, [key])

  // Relevé de la liste (premier affichage, changement de filtre, bouton, minuterie). La liste affichée reste en place
  // pendant le relevé et la sélection est conservée ; une réponse dépassée par une plus récente est ignorée.
  const reload = useCallback(async () => {
    const n = ++request.current
    setRefreshing(true)
    try {
      const r = await api('/tickets', { params })
      if (n !== request.current) return
      setItems(r.items); setTotal(r.total ?? r.items.length); setError('')
      setUpdatedAt(new Date()); lastLoad.current = Date.now()
      // Une ligne sortie de la liste (affectée ailleurs, close…) quitte aussi la sélection.
      const still = new Set(r.items.map((t) => t.ref))
      setPicked((s) => ([...s].every((ref) => still.has(ref)) ? s : new Set([...s].filter((ref) => still.has(ref)))))
    } catch (e) {
      if (n === request.current) setError(e.message)
    } finally {
      if (n === request.current) setRefreshing(false)
    }
  }, [params])
  useEffect(() => { reload() }, [reload])

  // Rafraîchissement automatique toutes les 45 s, seulement quand l'onglet est visible ; au retour sur l'onglet,
  // relevé immédiat si le dernier date de plus de 45 s.
  useEffect(() => {
    const visible = () => document.visibilityState === 'visible'
    const id = setInterval(() => { if (visible()) reload() }, REFRESH_MS)
    const onVisible = () => { if (visible() && Date.now() - lastLoad.current >= REFRESH_MS) reload() }
    document.addEventListener('visibilitychange', onVisible)
    return () => { clearInterval(id); document.removeEventListener('visibilitychange', onVisible) }
  }, [reload])

  useEffect(() => {
    if (isClient) return undefined
    let alive = true
    api('/tickets/counts', { params: { client: filters.client || undefined } }).then((r) => alive && setCounts(r)).catch(() => alive && setCounts(null))
    return () => { alive = false }
  }, [filters.client, isClient, items])

  useEffect(() => {
    if (isClient) return
    api('/me/filters').then((r) => setSaved(r.items)).catch(() => {})
  }, [isClient])

  const apply = (next) => { setPicked(new Set()); setMsg(''); setSearch(filtersToSearch(next), { replace: true }) }
  const set = (patch) => apply({ ...filters, ...patch })

  const saveFilter = async () => {
    const p = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== '' && v !== false))
    const r = await ask({
      title: tr('Enregistrer les filtres actuels comme filtre personnel'),
      body: <p>{tr("Le filtre apparaît dans la barre des vues, pour vous seul ; il reprend la recherche, les filtres et le tri affichés.")}</p>,
      fields: [{ name: 'name', label: tr('Nom du filtre'), maxLength: 80 }],
      confirm: tr('Enregistrer le filtre'),
      action: async ({ name }) => { await api('/me/filters', { method: 'POST', json: { name, params: p } }); return (await api('/me/filters')).items },
    })
    if (r) { setSaved(r.result); setMsg(tr('Filtre « {name} » enregistré.', { name: r.values.name })) }
  }
  const dropFilter = async (f) => {
    const r = await ask({
      title: tr('Supprimer le filtre enregistré « {name} » ?', { name: f.name }),
      body: <p>{tr("Seul le raccourci est supprimé : les tickets ne sont pas modifiés.")}</p>,
      confirm: tr('Supprimer le filtre'), danger: true,
      action: () => api(`/me/filters/${f.id}`, { method: 'DELETE' }),
    })
    if (r) { setSaved((list) => list.filter((x) => x.id !== f.id)); setMsg(tr('Filtre « {name} » supprimé.', { name: f.name })) }
  }

  const toggle = (ref) => setPicked((s) => { const n = new Set(s); n.has(ref) ? n.delete(ref) : n.add(ref); return n })
  const pageRefs = (items || []).map((t) => t.ref)
  const allPicked = pageRefs.length > 0 && pageRefs.every((ref) => picked.has(ref))
  const somePicked = pageRefs.some((ref) => picked.has(ref))
  useEffect(() => { if (selectAll.current) selectAll.current.indeterminate = somePicked && !allPicked }, [somePicked, allPicked])
  const toggleAll = () => setPicked(allPicked ? new Set() : new Set(pageRefs))

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

  const statusChoices = [
    ['', tr('Tous')], [OPEN_STATUSES, tr('Ouverts')], [TO_QUALIFY, tr('À qualifier')],
    ...Object.entries(STATUS).map(([k, v]) => [k, v.label]),
  ]
  const multi = me.clients.length > 1
  const cols = (isClient ? 9 : 11) + (multi ? 1 : 0)
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
        <>
          <section className="stats" aria-label={tr('Synthèse : filtres rapides')}>
            {CARDS.map((c) => <StatCard key={c.label} c={c} counts={counts} filters={filters} set={set} />)}
          </section>
          <section className="stats stats-priority" aria-label={tr('À traiter en priorité')}>
            {PRIORITIES.map((c) => <StatCard key={c.label} c={c} counts={counts} filters={filters} set={set} />)}
          </section>
        </>
      )}

      {!isClient && (
        <div className="row wrap gap views" role="group" aria-label={tr('Vues')}>
          {VIEWS.map(([label, assignee]) => (
            <button type="button" key={label} className={`vchip${filters.assignee === assignee ? ' on' : ''}`} aria-pressed={filters.assignee === assignee}
              onClick={() => set({ assignee })}>{tr(label)}</button>
          ))}
          {saved.length > 0 && <span className="muted small">{tr('Filtres :')}</span>}
          {saved.map((f) => (
            <span key={f.id} className="vchip saved">
              <button type="button" className="link" onClick={() => apply({ ...DEFAULTS, ...f.params })}>{f.name}</button>
              <button type="button" className="x" aria-label={tr('Supprimer le filtre {name}', { name: f.name })} onClick={() => dropFilter(f)}>×</button>
            </span>
          ))}
        </div>
      )}

      <section className="filters" aria-label={tr('Filtres')}>
        <form className="filter grow" role="search" onSubmit={(e) => { e.preventDefault(); set({ q: draftQ.trim() }) }}>
          <label>{tr('Recherche')}
            <input type="search" value={draftQ} onChange={(e) => setDraftQ(e.target.value)} placeholder={tr('Titre, règle, agent, IP, commentaire…')} />
          </label>
        </form>
        <label className="filter">{tr('Statut')}
          <select value={filters.status} onChange={(e) => set({ status: e.target.value })}>
            {statusChoices.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
            {!statusChoices.some(([k]) => k === filters.status) && <option value={filters.status}>{filters.status}</option>}
          </select>
        </label>
        <label className="filter">{tr('Gravité')}
          <select value={filters.severity} onChange={(e) => set({ severity: e.target.value })} title={tr('Gravité qualifiée ou, à défaut, criticité initiale')}>
            <option value="">{tr('Toutes')}</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{tr(s)}</option>)}
          </select>
        </label>
        {multi && (
          <label className="filter">{tr('Client')}
            <select value={filters.client} onChange={(e) => set({ client: e.target.value })}>
              <option value="">{tr("Tous")}</option>
              {me.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}
            </select>
          </label>
        )}
        <div className="row gap">
          <button type="button" onClick={() => apply(DEFAULTS)}>{tr('Réinitialiser')}</button>
          {!isClient && <button type="button" onClick={saveFilter}>{tr('Enregistrer ce filtre')}</button>}
        </div>
      </section>

      {error && <p className="error" role="alert">{error}</p>}
      {dialog}

      <div className="row wrap gap between list-bar">
        <p className="list-count" role="status">{items === null ? tr('Chargement…') : total > items.length
          ? tr('{n} tickets affichés sur {total} : affinez avec les filtres.', { n: items.length, total })
          : tr('{n} ticket(s)', { n: items.length })}</p>
        <div className="row gap refresh">
          <span className="muted small">{updatedAt ? tr('Mis à jour à {h}', { h: utcClock(updatedAt) }) : ''}</span>
          <button type="button" className="small-btn" onClick={reload} disabled={refreshing} title={tr('Relevé automatique toutes les 45 s quand cet onglet est affiché')}>{tr('Actualiser')}</button>
        </div>
      </div>
      <p className="live" role="status">{msg}</p>

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
        <table className="grid queue">
          <thead>
            <tr>
              {!isClient && <th scope="col" className="pick"><input ref={selectAll} type="checkbox" aria-label={tr('Sélectionner tous les tickets affichés')} checked={allPicked} disabled={pageRefs.length === 0} onChange={toggleAll} /></th>}
              <SortHeader label={tr('Réf.')} col="ref" filters={filters} set={set} /><th scope="col">{tr('Titre')}</th>
              {multi && <th scope="col">{tr('Client')}</th>}
              <SortHeader label={tr('Criticité')} col="criticite" filters={filters} set={set} />
              <SortHeader label={tr('Gravité')} col="gravite" filters={filters} set={set} />
              <SortHeader label={tr('Statut')} col="status" filters={filters} set={set} />
              <th scope="col">{tr('MITRE')}</th>
              {!isClient && <th scope="col">{tr('Assigné')}</th>}
              <SortHeader label={tr('Détecté (UTC)')} col="detected" filters={filters} set={set} /><th scope="col">{tr("TLP")}</th>
              <SortHeader label={tr('Occur.')} col="occurrences" filters={filters} set={set} className="num" />
            </tr>
          </thead>
          <tbody>
            {items === null && <tr><td colSpan={cols} className="muted">{tr('Chargement…')}</td></tr>}
            {items?.length === 0 && <tr><td colSpan={cols} className="muted">{tr('Aucun ticket ne correspond.')} <button type="button" className="link" onClick={() => apply(DEFAULTS)}>{tr('Retirer tous les filtres')}</button></td></tr>}
            {items?.map((t) => (
              <tr key={t.ref} className={t.overdue ? 'overdue' : ''}>
                {!isClient && <td className="pick"><input type="checkbox" aria-label={tr('Sélectionner {ref}', { ref: t.ref })} checked={picked.has(t.ref)} onChange={() => toggle(t.ref)} /></td>}
                <td className="mono"><Link to={`/tickets/${encodeURIComponent(t.ref)}`}>{t.ref}</Link></td>
                <td className="strong title-cell">{t.title}{t.overdue && <span className="pill danger" style={{ marginLeft: 8 }}>{tr('En retard')}</span>}{t.crisis && <span className="pill danger" style={{ marginLeft: 8 }}>{tr("CRISE")}</span>}</td>
                {multi && <td className="mono small" title={t.client}>{t.client_key}</td>}
                <td><Severity value={t.criticite_initiale} /></td>
                <td><Severity value={t.gravite} /></td>
                <td><Status value={t.status} />{t.rex_en_attente && <span className="pill warn">{tr("REX")}</span>}</td>
                <td title={`${tr('Source')} : ${MITRE_SOURCE[t.mitre_source]}`}><span className="mono">{t.mitre.join(', ') || '—'}</span></td>
                {!isClient && <td>{t.assignee || '—'}</td>}
                <td className="mono small">{utcShort(t.detected_at)}</td>
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
