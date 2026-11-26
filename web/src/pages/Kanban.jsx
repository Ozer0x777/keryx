import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Severity, Tlp } from '../components/Badges.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import { t as tr } from '../i18n.js'
import { KANBAN_COLUMNS, STATUS, TRANSITIONS } from '../labels.js'
import { confirmTransition, needsConfirm } from '../transitions.jsx'

// Statuts d'une colonne : les faux positifs sont rangés avec les tickets clos.
const columnStatuses = (s) => (s === 'cloture' ? 'cloture,faux_positif' : s)
const PER_COLUMN = 50     // cartes par colonne : les plus récentes ; les autres sont dans la liste paginée

export default function Kanban() {
  const [columns, setColumns] = useState(KANBAN_COLUMNS.map((status) => ({ status, cards: [], total: 0 })))
  const [mine, setMine] = useState(false)
  const [message, setMessage] = useState('')       // succès : zone live en tête de tableau
  const [loadError, setLoadError] = useState('')
  const [refused, setRefused] = useState(null)     // { ref, text } : refus affiché sur la carte concernée
  const [dragging, setDragging] = useState(null)
  const [ask, dialog] = useConfirm()

  // Une requête par colonne : chaque colonne montre ses cartes les plus récentes et son vrai total, quel que soit
  // le nombre de tickets (auparavant, 500 tickets au plus pour tout le tableau).
  const load = useCallback(() => Promise.all(KANBAN_COLUMNS.map((status) => api('/tickets', {
    params: { status: columnStatuses(status), limit: PER_COLUMN, assignee: mine ? 'me' : undefined },
  }).then((r) => ({ status, cards: r.items, total: r.total ?? r.items.length })))).then(setColumns), [mine])
  useEffect(() => { setLoadError(''); load().catch((e) => setLoadError(e.message)) }, [load])

  const move = async (ticket, target) => {
    if (ticket.status === target) return
    setMessage(''); setRefused(null)
    if (!TRANSITIONS[ticket.status]?.includes(target)) {
      setRefused({ ref: ticket.ref, text: tr('Passage impossible : {a} → {b}.', { a: STATUS[ticket.status].label, b: STATUS[target].label }) })
      return
    }
    const send = (reason) => api(`/tickets/${encodeURIComponent(ticket.ref)}/status`, { method: 'POST', json: reason ? { status: target, reason } : { status: target } })
    try {
      // Mêmes confirmations que la fiche ticket (motif du faux positif, étapes qui engagent le client) ; un refus du
      // serveur s'affiche dans le dialogue.
      if (needsConfirm(target)) {
        if (!(await confirmTransition(ask, { ref: ticket.ref, client: ticket.client, target, send }))) return
      } else await send()
      setMessage(`${ticket.ref} : ${STATUS[target].label}.`)
      await load()
    } catch (e) {
      setRefused({ ref: ticket.ref, text: e.message })
    }
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{tr('Kanban des incidents')}</h1>
          <p className="muted">{tr('Colonnes = phases ISO/IEC 27035 · glisser une carte change son statut (journalisé). Les faux positifs sont rangés avec les tickets clos.')}</p>
        </div>
        <div className="segmented" role="group" aria-label={tr('Type de vue')}>
          <Link to="/tickets">{tr('Liste')}</Link>
          <Link to="/kanban" className="on" aria-current="page">{tr("Kanban")}</Link>
        </div>
      </header>
      <label className="check"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} /> {tr('Mes tickets seulement')}</label>
      {loadError && <p className="error" role="alert">{loadError}</p>}
      <p className="live" role="status" aria-live="polite">{message}</p>
      {dialog}
      <div className="kanban">
        {columns.map((col) => (
          <section key={col.status} className={`column${dragging ? ' droppable' : ''}`} aria-label={STATUS[col.status].label}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); if (dragging) move(dragging, col.status); setDragging(null) }}>
            <header className="column-head">
              <span className="dot" aria-hidden="true" style={{ background: STATUS[col.status].color }} />
              <h2>{STATUS[col.status].label}</h2>
              <span className="count">{col.total}</span>
            </header>
            <p className="muted small">{STATUS[col.status].phase}</p>
            {col.cards.map((t) => (
              <article key={t.ref} className="kcard" draggable onDragStart={() => setDragging(t)} onDragEnd={() => setDragging(null)}>
                <Link to={`/tickets/${encodeURIComponent(t.ref)}`} className="kcard-title">{t.title}</Link>
                <div className="row wrap gap">
                  <Severity value={t.gravite || t.criticite_initiale} />
                  <span className="mono chip">{t.mitre[0] || tr('MITRE ?')}</span>
                  <Tlp value={t.tlp} />
                  {t.status === 'faux_positif' && <span className="pill">{tr("Faux positif")}</span>}
                  {t.rex_en_attente && <span className="pill warn">{tr("REX")}</span>}
                  {t.overdue && <span className="pill danger">{tr("En retard")}</span>}
                </div>
                <div className="row gap small muted">
                  <span className="mono ref">{t.ref}</span><span>{t.client}</span>
                  <span className="push">{t.assignee || tr('non assigné')}</span>
                </div>
                <label className="sr-only" htmlFor={`mv-${t.ref}`}>{tr('Changer le statut de {ref}', { ref: t.ref })}</label>
                <select id={`mv-${t.ref}`} className="move" value="" onChange={(e) => move(t, e.target.value)}>
                  <option value="">{tr("Déplacer…")}</option>
                  {(TRANSITIONS[t.status] || []).map((s) => <option key={s} value={s}>{STATUS[s].label}</option>)}
                </select>
                {refused?.ref === t.ref && <p className="error action-status" role="alert">{refused.text}</p>}
              </article>
            ))}
            {col.total > col.cards.length && (
              <Link className="small more" to={`/tickets?${new URLSearchParams({ status: columnStatuses(col.status), ...(mine ? { assignee: 'me' } : {}) })}`}>
                {tr('Voir les {n} autres dans la liste', { n: col.total - col.cards.length })}
              </Link>
            )}
          </section>
        ))}
      </div>
    </>
  )
}
