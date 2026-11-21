import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Severity, Tlp } from '../components/Badges.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import { t as tr } from '../i18n.js'
import { KANBAN_COLUMNS, STATUS, TRANSITIONS } from '../labels.js'

export default function Kanban() {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [mine, setMine] = useState(false)
  const [message, setMessage] = useState('')       // succès : zone live en tête de tableau
  const [loadError, setLoadError] = useState('')
  const [refused, setRefused] = useState(null)     // { ref, text } : refus affiché sur la carte concernée
  const [dragging, setDragging] = useState(null)
  const [ask, dialog] = useConfirm()

  const load = useCallback(() => api('/tickets', { params: { limit: 500, assignee: mine ? 'me' : undefined } }).then((r) => { setItems(r.items); setTotal(r.total ?? r.items.length) }), [mine])
  useEffect(() => { setLoadError(''); load().catch((e) => setLoadError(e.message)) }, [load])

  const move = async (ticket, target) => {
    if (ticket.status === target) return
    setMessage(''); setRefused(null)
    if (!TRANSITIONS[ticket.status]?.includes(target)) {
      setRefused({ ref: ticket.ref, text: tr('Passage impossible : {a} → {b}.', { a: STATUS[ticket.status].label, b: STATUS[target].label }) })
      return
    }
    const send = () => api(`/tickets/${encodeURIComponent(ticket.ref)}/status`, { method: 'POST', json: { status: target } })
    try {
      if (target === 'faux_positif') {
        // État terminal : confirmation avec la conséquence écrite ; un refus du serveur s'affiche dans le dialogue.
        const r = await ask({
          title: tr('Clore {ref} comme faux positif ?', { ref: ticket.ref }),
          body: <p>{tr("« Faux positif » est un état final : le ticket est clos, il ne pourra plus changer de statut ni être requalifié. Le verdict « Faux positif » doit avoir été enregistré dans la qualification.")}</p>,
          confirm: tr('Clore comme faux positif'), danger: true, action: send,
        })
        if (!r) return
      } else await send()
      setMessage(`${ticket.ref} : ${STATUS[target].label}.`)
      await load()
    } catch (e) {
      setRefused({ ref: ticket.ref, text: e.message })
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
      {total > items.length && <p className="muted small" role="status">{tr('{n} tickets affichés sur {total} : les plus anciens ne figurent pas dans le tableau.', { n: items.length, total })}</p>}
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
          </section>
        ))}
      </div>
    </>
  )
}
