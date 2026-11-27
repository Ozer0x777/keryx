import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import Pager from '../components/Pager.jsx'
import { dureeLisible, utcClock } from '../dates.js'
import { t as tr } from '../i18n.js'
import { STATUS } from '../labels.js'
import {
  cardActive, cardPatch, DEFAULTS, filtersFromSearch, filtersToSearch, OPEN_STATUSES, pageInfo, PER_PAGE, rememberQueue,
  SEVERITIES, TO_QUALIFY,
} from '../queue.js'

const REFRESH_MS = 45000
// Libellés sources (français) : traduits à l'affichage par tr(label).
const VIEWS = [['Tous', ''], ['Mes tickets', 'me'], ['Non assignés', 'none']]
// Cartes de chiffres : chacune est un filtre rapide (voir queue.js) et affiche le nombre de tickets qu'elle listerait.
// Les nombres viennent du point d'API de comptage (/tickets/counts), calculés par le serveur sur tous les tickets
// visibles : le relevé de la file ne recharge plus 500 tickets pour les compter.
const CARDS = [
  { label: 'Critiques non assignés', hint: 'ouverts, personne dessus', patch: { critical_unassigned: true }, count: (c) => c.critical_unassigned, hot: true },
  { label: 'En retard', hint: 'échéance dépassée', patch: { overdue: true }, count: (c) => c.overdue, hot: true },
  { label: 'À qualifier', hint: 'nouveaux ou en évaluation', patch: { status: TO_QUALIFY }, count: (c) => c.by_status.nouveau + c.by_status.en_evaluation },
  { label: 'En réponse', hint: 'confinement / éradication', patch: { status: 'en_reponse' }, count: (c) => c.by_status.en_reponse },
  { label: 'Critiques ouverts', hint: 'gravité ou criticité', patch: { status: OPEN_STATUSES, severity: 'Critique' }, count: (c) => c.open_by_severity.Critique },
  { label: 'REX en attente', hint: 'obligatoire si Élevée ou Critique', patch: { rex_en_attente: true }, count: (c) => c.rex_en_attente },
]
// Vues de priorisation (ADR-0025) : ce qui demande une action de l'équipe. Chacune a son propre critère, calculé par le
// serveur ; aucune ne modifie la vue d'assigné (Tous, Mes tickets, Non assignés).
const PRIORITIES = [
  { label: 'En attente du client', hint: 'sa réponse n\'est pas arrivée', patch: { awaiting_client: true }, count: (c) => c.awaiting_client },
  { label: 'Dossiers incomplets', hint: 'gravité, assigné ou synthèse manquants', patch: { incomplete: true }, count: (c) => c.incomplete },
]

// Date de détection sans le suffixe « UTC » (il est dans l'en-tête de colonne) : la colonne reste étroite.
const utcShort = (iso) => (iso ? iso.replace('T', ' ').slice(0, 16) : '—')
const ago = (iso) => (iso ? tr('il y a {d}', { d: dureeLisible((Date.now() - new Date(iso).getTime()) / 1000) }) : '')
const DEFAULT_TLP = 'TLP:AMBER'          // marquage d'un client sans plancher

// Échéance la plus proche (qualification ou résolution) : temps restant, en couleur ; dépassée en rouge.
export function Echeance({ t }) {
  const cands = [['qualifier', t.due_qualification], ['résoudre', t.due_resolution]].filter(([, d]) => d)
  if (!cands.length) return <span className="sla none">—</span>
  const [what, due] = cands.reduce((a, b) => (a[1] <= b[1] ? a : b))
  const left = (new Date(due).getTime() - Date.now()) / 1000
  const cls = left < 0 ? 'late' : left < 2 * 3600 ? 'warn' : 'ok'
  const text = left < 0 ? tr('{w} : dépassée de {d}', { w: tr(what), d: dureeLisible(-left) }) : tr('{w} : {d}', { w: tr(what), d: dureeLisible(left) })
  return <span className={`sla ${cls}`} title={`${tr(what)} ${tr('avant')} ${due.replace('T', ' ').slice(0, 16)} UTC`}>{text}</span>
}

// Assigné en initiales (nom complet en infobulle et pour les lecteurs d'écran) ; cercle en pointillé si personne.
function Avatar({ name }) {
  if (!name) return <span className="av empty" title={tr('Non assigné')}><span aria-hidden="true">?</span><span className="sr-only">{tr('Non assigné')}</span></span>
  const ini = name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()
  return <span className="av" title={name}><span aria-hidden="true">{ini}</span><span className="sr-only">{name}</span></span>
}

// Contexte sous le titre : agent, adresse, client (si plusieurs) ; TLP seulement s'il diffère du plancher du client.
function Contexte({ t, multi }) {
  const tlpDiff = t.tlp !== (t.tlp_plancher || DEFAULT_TLP)
  return (
    <span className="ctx">
      {[t.agent_name, t.agent_ip, multi ? t.client : null].filter(Boolean).join(' · ')}
      {tlpDiff && <> <Tlp value={t.tlp} /></>}
    </span>
  )
}

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
    <button type="button" className={`card stat stat-filter${on ? ' on' : ''}${c.hot && counts && c.count(counts) > 0 ? ' hot' : ''}`} aria-pressed={on}
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
  // Équipe : la file est triée par échéance tant qu'aucun tri n'est choisi ; le client garde le tri par date.
  const filters = useMemo(() => {
    const f = filtersFromSearch(search)
    return !isClient && !search.has('sort') ? { ...f, sort: 'echeance', order: 'asc' } : f
  }, [search, isClient])
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
    if (!isClient && !new URLSearchParams(key).has('sort')) { f.sort = 'echeance'; f.order = 'asc' }   // tri par défaut de l'équipe
    return { ...f, rex_en_attente: f.rex_en_attente || undefined, overdue: f.overdue || undefined,
      critical_unassigned: f.critical_unassigned || undefined, awaiting_client: f.awaiting_client || undefined,
      incomplete: f.incomplete || undefined, limit: Number(f.per_page), offset: (Number(f.page) - 1) * Number(f.per_page) }
  }, [key, isClient])

  // Relevé de la liste (premier affichage, changement de filtre, bouton, minuterie). La liste affichée reste en place
  // pendant le relevé et la sélection est conservée ; une réponse dépassée par une plus récente est ignorée.
  const reload = useCallback(async () => {
    const n = ++request.current
    setRefreshing(true)
    try {
      const r = await api('/tickets', { params })
      if (n !== request.current) return
      const pi = pageInfo(r.total ?? r.items.length, params.offset / params.limit + 1, params.limit)
      if (pi.page !== params.offset / params.limit + 1) {
        // Page au-delà de la fin (tickets clos ou filtrés entre-temps) : aller à la dernière page qui existe.
        setSearch((sp) => { const n = new URLSearchParams(sp); n.set('page', String(pi.page)); return n }, { replace: true })
        return
      }
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
  }, [params, setSearch])
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

  // Un filtre, un tri ou une vue qui change ramène à la première page ; changer de page garde l'historique (Précédent).
  // Le tri par défaut de l'équipe (échéance, ordre croissant) n'est pas écrit dans l'URL : sans filtre, l'URL reste vide.
  const base = isClient ? DEFAULTS : { ...DEFAULTS, sort: 'echeance', order: 'asc' }
  const toSearch = (f) => {
    const out = filtersToSearch(f)
    if (!isClient && f.sort === 'echeance' && f.order === 'asc') { delete out.sort; delete out.order }
    else if (!isClient && f.sort === DEFAULTS.sort && f.order === DEFAULTS.order) { out.sort = f.sort }   // choix explicite
    return out
  }
  const apply = (next) => { setPicked(new Set()); setMsg(''); setSearch(toSearch({ ...next, page: '1' }), { replace: true }) }
  const goPage = (page) => { setPicked(new Set()); setMsg(''); setSearch(toSearch({ ...filters, page: String(page) })) }
  const pages = pageInfo(total, filters.page, filters.per_page)
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
    ['', tr('Tous')], [OPEN_STATUSES, tr('Ouverts')], [TO_QUALIFY, tr('À qualifier')], ['cloture,faux_positif', tr('Clôturés et faux positifs')],
    ...Object.entries(STATUS).map(([k, v]) => [k, v.label]),
  ]
  const multi = me.clients.length > 1
  const cols = isClient ? 9 + (multi ? 1 : 0) : 10
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
          <section className="stats stats-row" aria-label={tr('Synthèse : filtres rapides')}>
            {[...CARDS, ...PRIORITIES].map((c) => <StatCard key={c.label} c={c} counts={counts} filters={filters} set={set} />)}
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
              <button type="button" className="link" onClick={() => apply({ ...base, ...f.params })}>{f.name}</button>
              <button type="button" className="x" aria-label={tr('Supprimer le filtre {name}', { name: f.name })} onClick={() => dropFilter(f)}>×</button>
            </span>
          ))}
        </div>
      )}

      <section className="filters" aria-label={tr('Filtres')}>
        <form className="filter grow" role="search" onSubmit={(e) => { e.preventDefault(); set({ q: draftQ.trim() }) }}>
          <label>{tr('Recherche')}
            <input type="search" value={draftQ} onChange={(e) => setDraftQ(e.target.value)}
              placeholder={isClient ? tr('Titre, règle, agent, IP, commentaire…') : tr('ex. ACME-12, ip:185.220.101.4, compte:admin, ou un mot')}
              title={isClient ? undefined : tr('Par champ : ip:, hote:, agent:, regle:, compte:, hash:, domaine:, ref: ; ou texte libre (titre, description, alerte brute, commentaires).')} />
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
          <button type="button" onClick={() => apply(base)}>{tr('Réinitialiser')}</button>
          {!isClient && <button type="button" onClick={saveFilter}>{tr('Enregistrer ce filtre')}</button>}
        </div>
      </section>

      {error && <p className="error" role="alert">{error}</p>}
      {dialog}

      <div className="row wrap gap between list-bar">
        <p className="list-count" role="status">{items === null ? tr('Chargement…') : total > items.length
          ? tr('Tickets {from} à {to} sur {total}', { from: pages.from, to: pages.to, total })
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
              {isClient ? (<>
                <SortHeader label={tr('Réf.')} col="ref" filters={filters} set={set} /><th scope="col">{tr('Titre')}</th>
                {multi && <th scope="col">{tr('Client')}</th>}
                <SortHeader label={tr('Criticité')} col="criticite" filters={filters} set={set} />
                <SortHeader label={tr('Gravité')} col="gravite" filters={filters} set={set} />
                <SortHeader label={tr('Statut')} col="status" filters={filters} set={set} />
                <th scope="col">{tr('MITRE')}</th>
                <SortHeader label={tr('Détecté (UTC)')} col="detected" filters={filters} set={set} /><th scope="col">{tr("TLP")}</th>
                <SortHeader label={tr('Occur.')} col="occurrences" filters={filters} set={set} className="num" />
              </>) : (<>
                {/* Équipe : contexte sous le titre, règle, criticité, gravité, occurrences, statut, échéance, assigné. */}
                <th scope="col" className="pick"><input ref={selectAll} type="checkbox" aria-label={tr('Sélectionner tous les tickets affichés')} checked={allPicked} disabled={pageRefs.length === 0} onChange={toggleAll} /></th>
                <SortHeader label={tr('Réf.')} col="ref" filters={filters} set={set} /><th scope="col">{tr('Incident')}</th>
                <th scope="col">{tr('Règle')}</th>
                <SortHeader label={tr('Criticité')} col="criticite" filters={filters} set={set} />
                <SortHeader label={tr('Gravité')} col="gravite" filters={filters} set={set} />
                <SortHeader label={tr('Occur.')} col="occurrences" filters={filters} set={set} className="num" />
                <SortHeader label={tr('Statut')} col="status" filters={filters} set={set} />
                <SortHeader label={tr('Échéance')} col="echeance" filters={filters} set={set} />
                <th scope="col"><span className="sr-only">{tr('Assigné')}</span></th>
              </>)}
            </tr>
          </thead>
          <tbody>
            {items === null && <tr><td colSpan={cols} className="muted">{tr('Chargement…')}</td></tr>}
            {items?.length === 0 && <tr><td colSpan={cols} className="muted">{tr('Aucun ticket ne correspond.')} <button type="button" className="link" onClick={() => apply(base)}>{tr('Retirer tous les filtres')}</button></td></tr>}
            {items?.map((t) => (
              isClient ? (
              <tr key={t.ref}>
                <td className="mono"><Link to={`/tickets/${encodeURIComponent(t.ref)}`}>{t.ref}</Link></td>
                <td className="strong title-cell">{t.title}</td>
                {multi && <td className="mono small" title={t.client}>{t.client_key}</td>}
                <td><Severity value={t.criticite_initiale} /></td>
                <td><Severity value={t.gravite} /></td>
                <td><Status value={t.status} /></td>
                <td><span className="mono">{t.mitre.join(', ') || '—'}</span></td>
                <td className="mono small">{utcShort(t.detected_at)}</td>
                <td><Tlp value={t.tlp} /></td>
                <td className="num mono">{t.occurrences}</td>
              </tr>
              ) : (
              <tr key={t.ref} className={t.overdue ? 'overdue' : ''}>
                <td className="pick"><input type="checkbox" aria-label={tr('Sélectionner {ref}', { ref: t.ref })} checked={picked.has(t.ref)} onChange={() => toggle(t.ref)} /></td>
                <td className="mono"><Link to={`/tickets/${encodeURIComponent(t.ref)}`}>{t.ref}</Link></td>
                <td className="title-cell"><span className="strong">{t.title}</span>{t.crisis && <> <span className="pill danger">{tr("CRISE")}</span></>}{t.rex_en_attente && <> <span className="pill warn">{tr("REX")}</span></>}
                  <Contexte t={t} multi={multi} /></td>
                <td><span className="rule-chip mono">{t.rule_id || '—'}</span></td>
                <td><Severity value={t.criticite_initiale} /></td>
                <td>{t.gravite ? <Severity value={t.gravite} /> : <span className="muted">—</span>}</td>
                <td className="num"><span className="mono">{t.occurrences}</span><span className="occ-last">{ago(t.last_seen_at)}</span></td>
                <td><Status value={t.status} /></td>
                <td><Echeance t={t} /></td>
                <td><Avatar name={t.assignee} /></td>
              </tr>
              )
            ))}
          </tbody>
        </table>
      </div>
      {items !== null && (total > Number(PER_PAGE[0]) || pages.pages > 1) && (
        <Pager info={pages} label={tr('Pages de la liste')} onPage={goPage} perPage={filters.per_page}
          perPageOptions={PER_PAGE} onPerPage={(v) => set({ per_page: v })} perPageLabel={tr('Tickets par page')} />
      )}
      <p className="muted small">{tr('Criticité initiale calculée depuis le niveau de règle Wazuh · gravité fixée à la qualification.')}</p>
    </>
  )
}
