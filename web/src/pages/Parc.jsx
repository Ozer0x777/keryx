import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, downloadBlob } from '../api.js'
import { useAuth } from '../App.jsx'
import { ActionStatus, useActionStatus } from '../components/ActionStatus.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'

// Parc d'agents Wazuh (ADR-0030) : état, version et disponibilité des agents d'un client, relevés en lecture seule dans
// l'API du manager. Équipe : tout, relevé à la demande, export, ticket « agent déconnecté ». Client : son parc seulement.
// Filtres, recherche et agent choisi vivent dans l'URL (retour arrière, lien partagé).

const STATUS = {
  active: { label: 'Actif', cls: 'ok' },
  disconnected: { label: 'Déconnecté', cls: 'danger' },
  never_connected: { label: 'Jamais connecté', cls: '' },
  pending: { label: 'En attente', cls: 'warn' },
  removed: { label: 'Retiré de Wazuh', cls: '' },
  inconnu: { label: 'Pas encore observé', cls: '' },
}
const GAP = { retard: 'en retard', tres_ancienne: 'très ancienne', plus_recente: 'plus récente que le manager' }

const FILTERS = [
  ['all', 'Agents', 'enregistrés chez le client', () => true],
  ['active', 'Actifs', 'contact récent avec le manager', (a) => a.status === 'active'],
  ['disconnected', 'Déconnectés', 'plus de contact', (a) => a.status === 'disconnected'],
  ['down24', 'Hors ligne > 24 h', 'à traiter en priorité', (a) => a.down24],
  ['never', 'Jamais connectés', 'ou en attente d’enregistrement', (a) => a.status === 'never_connected' || a.status === 'pending'],
  ['outdated', 'Versions en retard', 'plus anciennes que le manager', (a) => a.outdated],
  ['silent', 'Silencieux', 'actifs, aucun événement depuis 24 h', (a) => a.silent === true],
]

// Durée lisible, de la seconde au jour.
export function duration(fromIso, now = Date.now()) {
  if (!fromIso) return '—'
  const s = Math.max(0, Math.round((now - Date.parse(fromIso)) / 1000))
  if (s < 60) return tr('{n} s', { n: s })
  const m = Math.floor(s / 60)
  if (m < 60) return tr('{n} min', { n: m })
  const h = Math.floor(m / 60)
  if (h < 48) return tr('{h} h {m} min', { h, m: String(m % 60).padStart(2, '0') })
  return tr('{d} j {h} h', { d: Math.floor(h / 24), h: h % 24 })
}

function StatusPill({ status }) {
  const s = STATUS[status] || STATUS.inconnu
  return <span className={`pill ${s.cls}`}><span className="dot" aria-hidden="true" />{tr(s.label)}</span>
}

export default function Parc() {
  const { me } = useAuth()
  const team = me.role === 'analyst' || me.role === 'manager'
  const [search, setSearch] = useSearchParams()
  const client = search.get('client') || ''
  const filter = FILTERS.some(([k]) => k === search.get('filtre')) ? search.get('filtre') : 'all'
  const q = search.get('q') || ''
  const selected = search.get('agent') || ''
  const [p, setP] = useState(null)
  const [error, setError] = useState('')
  const [status, track] = useActionStatus()

  const setParam = useCallback((patch) => setSearch((cur) => {
    const n = new URLSearchParams(cur)
    for (const [k, v] of Object.entries(patch)) { if (v) n.set(k, v); else n.delete(k) }
    return n
  }, { replace: true }), [setSearch])

  const load = useCallback(() => api('/parc', { params: { client: client || undefined } })
    .then((r) => { setP(r); setError('') }).catch((e) => setError(e.message)), [client])
  useEffect(() => { load() }, [load])

  const refresh = () => track(async () => { await api(`/parc/${p.client.key}/refresh`, { method: 'POST' }); await load() }, tr('Relevé terminé.'))
  const exportCsv = () => track(async () => {
    downloadBlob(await api(`/parc/${p.client.key}/export.csv`), `parc-${p.client.key}.csv`)
  }, tr('Export téléchargé.'))

  const counts = useMemo(() => Object.fromEntries(FILTERS.map(([k, , , fn]) => [k, (p?.agents || []).filter(fn).length])), [p])
  const rows = useMemo(() => {
    if (!p) return []
    const fn = FILTERS.find(([k]) => k === filter)[3]
    const needle = q.trim().toLowerCase()
    return p.agents.filter(fn)
      .filter((a) => !needle || [a.name, a.id, a.ip, a.os, (a.groups || []).join(' ')].join(' ').toLowerCase().includes(needle))
      .sort((a, b) => (b.down24 - a.down24) || ((b.status === 'disconnected') - (a.status === 'disconnected'))
        || (a.status === 'disconnected' ? Date.parse(a.status_since) - Date.parse(b.status_since) : 0) || a.name.localeCompare(b.name))
  }, [p, filter, q])

  if (error) return <p className="error" role="alert">{error}</p>
  if (!p) return <p className="loading">{tr('Chargement…')}</p>
  const down24 = p.agents.filter((a) => a.down24)
  const filters = FILTERS.filter(([k]) => k !== 'silent' || p.events_known)

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{team ? tr("Parc d'agents Wazuh") : tr("Mon parc d'agents Wazuh")}</h1>
          <p className="muted">{team
            ? tr("État des agents de chaque client, lu en lecture seule dans l'API du manager Wazuh. Keryx n'agit jamais sur Wazuh.")
            : tr('Les machines de votre organisation surveillées par le SOC, et leur état.')}</p>
        </div>
        <div className="row wrap gap">
          {p.clients.length > 1 && (
            <label className="filter">{tr('Client')}
              <select value={p.client.key} onChange={(e) => setParam({ client: e.target.value, agent: '' })}>
                {p.clients.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}
              </select>
            </label>
          )}
          {team && p.configured && <button type="button" onClick={refresh}>{tr('Relever maintenant')}</button>}
          {team && p.agents.length > 0 && <button type="button" onClick={exportCsv}>{tr('Exporter (CSV)')}</button>}
        </div>
      </header>
      <ActionStatus state={status} live />

      {!p.configured && p.agents.length === 0 ? (
        <p className="banner">{team
          ? tr("Le suivi du parc n'est pas activé pour ce client : un Admin règle l'accès à l'API du manager Wazuh (Administration, Clients).")
          : tr("Le suivi de votre parc n'est pas activé. Votre contact au SOC peut le mettre en place.")}</p>
      ) : (
        <>
          <section className="parc-source card" aria-label={tr('Source des données')}>
            <span><span className="muted strong">{tr('Manager')}</span> {tr('version')} <span className="mono">{p.manager_version || '—'}</span></span>
            <span><span className="muted strong">{tr('Dernier relevé')}</span> {p.polled_at ? tr('il y a {d}', { d: duration(p.polled_at) }) : tr('aucun')}
              {p.poll_interval_s > 0 && <span className="muted"> {tr('(toutes les {n} min)', { n: Math.round(p.poll_interval_s / 60) })}</span>}</span>
            {team && <span><span className="muted strong">{tr('Dernier événement')}</span> {p.events_known ? tr("lu dans l'indexeur") : tr('indexeur non relié')}</span>}
            {p.error && <span className="pill danger">{team ? p.error : tr("Le dernier relevé a échoué : l'état affiché peut être ancien.")}</span>}
          </section>

          {down24.length > 0 && (
            <div className="banner danger row wrap gap between" role="status">
              <span><strong>{tr('{n} agent(s) hors ligne depuis plus de 24 h.', { n: down24.length })}</strong> {tr("Les alertes de ces machines n'arrivent plus au SOC.")}</span>
              {filter !== 'down24' && <button type="button" onClick={() => setParam({ filtre: 'down24' })}>{tr('Voir ces agents')}</button>}
            </div>
          )}

          <section className="stats" aria-label={tr('Synthèse : filtres rapides')}>
            {filters.map(([k, label, hint]) => {
              const on = filter === k
              return (
                <button type="button" key={k} className={`card stat stat-filter${on ? ' on' : ''}`} aria-pressed={on}
                  onClick={() => setParam({ filtre: on || k === 'all' ? '' : k })}>
                  <span className="stat-label">{tr(label)}</span>
                  <strong>{counts[k]}</strong>
                  <span className="stat-hint small">{on && k !== 'all' ? tr('filtre actif') : tr(hint)}</span>
                </button>
              )
            })}
          </section>

          <div className="parc-layout">
            <section className="parc-main" aria-label={tr('Agents')}>
              <div className="row wrap gap between">
                <label className="filter grow">{tr('Recherche')}
                  <input type="search" value={q} placeholder={tr('Nom, identifiant, adresse, système, groupe…')} onChange={(e) => setParam({ q: e.target.value })} />
                </label>
                <p className="muted small" role="status">{tr('{n} agent(s) affiché(s) sur {total}', { n: rows.length, total: p.agents.length })}</p>
              </div>
              <div className="table-wrap card">
                <table className="grid">
                  <thead><tr>
                    <th scope="col">{tr('État')}</th><th scope="col">{tr('Agent')}</th><th scope="col">{tr('Système')}</th>
                    <th scope="col">{tr('Version')}</th><th scope="col">{tr('Hors ligne depuis')}</th>
                    <th scope="col">{p.events_known ? tr('Dernier événement') : tr('Dernier contact')}</th>
                    {team && <th scope="col" className="num">{tr('Tickets')}</th>}
                  </tr></thead>
                  <tbody>
                    {rows.length === 0 && <tr><td colSpan={team ? 7 : 6} className="muted">{tr('Aucun agent ne correspond.')} <button type="button" className="link" onClick={() => setParam({ filtre: '', q: '' })}>{tr('Retirer les filtres')}</button></td></tr>}
                    {rows.map((a) => (
                      <tr key={a.id} className={a.id === selected ? 'selected' : ''}>
                        <td><StatusPill status={a.status} /></td>
                        <td><button type="button" className="link strong" aria-label={tr('Voir le détail de {name}', { name: a.name })} onClick={() => setParam({ agent: a.id })}>{a.name}</button>
                          <div className="mono small muted">{a.id}{a.ip ? ` · ${a.ip}` : ''}</div></td>
                        <td>{a.os || '—'}</td>
                        <td className="nowrap"><span className="mono">{a.version || '—'}</span>{a.version_gap && <> <span className="pill warn">{tr(GAP[a.version_gap])}</span></>}</td>
                        <td className={a.down24 ? 'danger-text strong nowrap' : 'nowrap'}>{a.status === 'disconnected' ? duration(a.status_since) : a.status === 'never_connected' ? tr('jamais connecté') : '—'}</td>
                        <td className={a.silent ? 'warn-text strong nowrap' : 'nowrap'}>{p.events_known
                          ? (a.last_event_at ? tr('il y a {d}', { d: duration(a.last_event_at) }) : tr('aucun depuis 30 j'))
                          : (a.last_keepalive ? tr('il y a {d}', { d: duration(a.last_keepalive) }) : '—')}</td>
                        {team && <td className="num mono">{a.open_tickets}</td>}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Versions versions={p.versions} manager={p.manager_version} />
            </section>
            <AgentDetail key={`${p.client.key}-${selected}`} p={p} id={selected || rows[0]?.id} team={team} onChanged={load} />
          </div>
        </>
      )}
    </>
  )
}

function Versions({ versions, manager }) {
  if (!versions.length) return null
  const max = Math.max(...versions.map((v) => v.count))
  return (
    <section className="card section" aria-label={tr('Versions des agents')}>
      <h2>{tr('Versions des agents')}</h2>
      <p className="muted small">{tr("Un agent ne doit pas être plus récent que son manager ({m}) ; plus ancien, il lui manque des correctifs et des règles de détection.", { m: manager || '—' })}</p>
      <ul className="parc-versions">
        {versions.map((v) => (
          <li key={v.version}>
            <span className="mono">{v.version}</span>
            <span className="bar" aria-hidden="true"><span className={`fill ${v.gap ? (v.gap === 'retard' ? 'warn' : 'danger') : 'ok'}`} style={{ width: `${Math.round(v.count / max * 100)}%` }} /></span>
            <span>{tr('{n} agent(s)', { n: v.count })} · {v.gap ? tr(GAP[v.gap]) : tr('à jour')}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function AgentDetail({ p, id, team, onChanged }) {
  const [d, setD] = useState(null)
  const [error, setError] = useState('')
  const [status, track] = useActionStatus()
  const [ask, dialog] = useConfirm()
  useEffect(() => {
    if (!id) return
    api(`/parc/${p.client.key}/agents/${encodeURIComponent(id)}`).then(setD).catch((e) => setError(e.message))
  }, [p, id])
  if (!id) return null
  if (error) return <aside className="parc-detail card" aria-label={tr("Détail de l'agent")}><p className="error" role="alert">{error}</p></aside>
  if (!d) return <aside className="parc-detail card" aria-label={tr("Détail de l'agent")}><p className="muted">{tr('Chargement…')}</p></aside>
  const openTicket = async () => {
    const r = await ask({
      title: tr('Ouvrir un ticket « agent déconnecté » pour {name} ?', { name: d.name }),
      body: <p>{tr("Le ticket passe par la même file que les alertes Wazuh : s'il en existe déjà un ouvert pour cet agent, il est complété au lieu d'être dupliqué. Le client le verra comme ses autres incidents.")}</p>,
      confirm: tr('Ouvrir le ticket'),
      action: () => api(`/parc/${p.client.key}/agents/${encodeURIComponent(d.id)}/ticket`, { method: 'POST' }),
    })
    if (r) { track(async () => {}, tr('Ticket {ref} : {s}.', { ref: r.result.ref, s: r.result.status === 'created' ? tr('créé') : tr('complété') })); onChanged() }
  }
  const segLabel = d.timeline_7d.map((s) => `${tr((STATUS[s.status] || STATUS.inconnu).label)} ${Math.round(s.share * 100)} %`).join(', ')
  return (
    <aside className="parc-detail card" aria-label={tr("Détail de l'agent")}>
      <div>
        <p className="muted small strong">{tr('Agent sélectionné')}</p>
        <h2>{d.name}</h2>
        <p className="mono small muted">{d.id}{d.ip ? ` · ${d.ip}` : ''}{team && d.node ? ` · ${tr('nœud')} ${d.node}` : ''}</p>
        <StatusPill status={d.status} />
        {d.status !== 'active' && <span className="muted small"> {tr('depuis {d}', { d: duration(d.status_since) })}</span>}
      </div>
      <div>
        <h3>{tr('Disponibilité sur 7 jours : {p}', { p: d.availability_7d == null ? tr('non mesurée') : `${d.availability_7d} %` })}</h3>
        <div className="parc-timeline" role="img" aria-label={tr('Disponibilité sur 7 jours : {s}', { s: segLabel })}>
          {d.timeline_7d.map((s, i) => <span key={i} className={`seg ${s.status}`} style={{ flexBasis: `${s.share * 100}%` }} />)}
        </div>
        <div className="row between muted small"><span>{tr('il y a 7 j')}</span><span>{tr('maintenant')}</span></div>
        <p className="muted small">{tr('Sur 30 jours : {p}.', { p: d.availability_30d == null ? tr('non mesurée') : `${d.availability_30d} %` })}</p>
      </div>
      <dl className="kv">
        <dt>{tr('Système')}</dt><dd>{d.os || '—'}</dd>
        <dt>{tr('Version')}</dt><dd><span className="mono">{d.version || '—'}</span> {d.version_gap ? `(${tr(GAP[d.version_gap])} ; ${tr('manager')} ${p.manager_version})` : d.version ? tr('(à jour)') : ''}</dd>
        <dt>{tr('Groupes')}</dt><dd className="mono small">{(d.groups || []).join(', ') || '—'}</dd>
        {d.importance && <><dt>{tr('Importance')}</dt><dd>{tr(d.importance)}</dd></>}
        <dt>{tr('Dernier contact')}</dt><dd>{d.last_keepalive ? formatUtc(d.last_keepalive) : tr('jamais')}</dd>
        {p.events_known && <><dt>{tr('Dernier événement')}</dt><dd>{d.last_event_at ? formatUtc(d.last_event_at) : tr('aucun depuis 30 j')}</dd></>}
        <dt>{tr('Enregistré le')}</dt><dd>{d.registered_at ? formatUtc(d.registered_at) : '—'}</dd>
      </dl>
      <div>
        <h3>{tr("Changements d'état")}</h3>
        <ol className="parc-changes">
          {d.changes.map((c, i) => (
            <li key={i}><span className="mono small muted">{formatUtc(c.at)}</span><span>{tr((STATUS[c.status] || STATUS.inconnu).label)}</span></li>
          ))}
        </ol>
        <p className="muted small">{tr("Historique conservé depuis le premier relevé de Keryx.")}</p>
      </div>
      {team && (
        <div className="row wrap gap">
          {d.status === 'disconnected' && <button type="button" className="primary" onClick={openTicket}>{tr('Ouvrir un ticket « agent déconnecté »')}</button>}
          {(d.tickets || []).map((ref) => <Link key={ref} className="btn-link" to={`/tickets/${encodeURIComponent(ref)}`}>{ref}</Link>)}
        </div>
      )}
      <ActionStatus state={status} />
      {dialog}
    </aside>
  )
}
