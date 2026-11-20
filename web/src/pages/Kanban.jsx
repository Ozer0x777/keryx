import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Severity, Tlp } from '../components/Badges.jsx'
import { KANBAN_COLUMNS, STATUS, TRANSITIONS } from '../labels.js'

export default function Kanban() {
  const [items, setItems] = useState([])
  const [message, setMessage] = useState('')
  const [dragging, setDragging] = useState(null)

  const load = useCallback(() => api('/tickets', { params: { limit: 500 } }).then((r) => setItems(r.items)), [])
  useEffect(() => { load().catch((e) => setMessage(e.message)) }, [load])

  const move = async (ticket, target) => {
    if (ticket.status === target) return
    if (!TRANSITIONS[ticket.status]?.includes(target)) {
      setMessage(`Passage impossible : ${STATUS[ticket.status].label} → ${STATUS[target].label}.`)
      return
    }
    try {
      await api(`/tickets/${encodeURIComponent(ticket.ref)}/status`, { method: 'POST', json: { status: target } })
      setMessage(`${ticket.ref} : ${STATUS[target].label}.`)
      await load()
    } catch (e) {
      setMessage(`${ticket.ref} : ${e.message}`)
    }
  }

  const columns = KANBAN_COLUMNS.map((s) => ({
    status: s,
    cards: items.filter((t) => t.status === s || (s === 'cloture' && t.status === 'faux_positif')),
  }))

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Kanban des incidents</h1>
          <p className="muted">Colonnes = phases ISO/IEC 27035 · glisser une carte change son statut (journalisé). Les faux positifs sont rangés avec les tickets clos.</p>
        </div>
        <div className="segmented" role="group" aria-label="Type de vue">
          <Link to="/tickets">Liste</Link>
          <Link to="/kanban" className="on" aria-current="page">Kanban</Link>
        </div>
      </header>
      <p className="live" role="status" aria-live="polite">{message}</p>
      <div className="kanban">
        {columns.map((col) => (
          <section key={col.status} className={`column${dragging ? ' droppable' : ''}`} aria-label={STATUS[col.status].label}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); if (dragging) move(dragging, col.status); setDragging(null) }}>
            <header className="column-head">
              <span className="dot" aria-hidden="true" style={{ background: STATUS[col.status].color }} />
              <h2>{STATUS[col.status].label}</h2>
              <span className="count">{col.cards.length}</span>
            </header>
            <p className="muted small">{STATUS[col.status].phase}</p>
            {col.cards.map((t) => (
              <article key={t.ref} className="kcard" draggable onDragStart={() => setDragging(t)} onDragEnd={() => setDragging(null)}>
                <Link to={`/tickets/${encodeURIComponent(t.ref)}`} className="kcard-title">{t.title}</Link>
                <div className="row wrap gap">
                  <Severity value={t.gravite || t.criticite_initiale} />
                  <span className="mono chip">{t.mitre[0] || 'MITRE ?'}</span>
                  <Tlp value={t.tlp} />
                  {t.status === 'faux_positif' && <span className="pill">Faux positif</span>}
                  {t.rex_en_attente && <span className="pill warn">REX</span>}
                </div>
                <div className="row gap small muted">
                  <span className="mono ref">{t.ref}</span><span>{t.client}</span>
                  <span className="push">{t.assignee || 'non assigné'}</span>
                </div>
                <label className="sr-only" htmlFor={`mv-${t.ref}`}>Changer le statut de {t.ref}</label>
                <select id={`mv-${t.ref}`} className="move" value="" onChange={(e) => move(t, e.target.value)}>
                  <option value="">Déplacer…</option>
                  {(TRANSITIONS[t.status] || []).map((s) => <option key={s} value={s}>{STATUS[s].label}</option>)}
                </select>
              </article>
            ))}
          </section>
        ))}
      </div>
    </>
  )
}
