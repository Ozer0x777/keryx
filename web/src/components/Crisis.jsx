import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { formatUtc } from '../labels.js'

const KINDS = { decision: 'Décisions', action: "Plan d'action", synthese: 'Synthèse de crise' }

// Registre de crise d'un ticket. [PRIS VI.5.5.1] Texte brut : jamais interprété comme du HTML.
export default function Crisis({ t, enc, isManager, open, onChange }) {
  const [c, setC] = useState(null)
  const [error, setError] = useState('')
  const [kind, setKind] = useState('decision')
  const load = useCallback(() => api(`/tickets/${enc}/crisis`).then(setC).catch((e) => setError(e.message)), [enc])
  useEffect(() => { load() }, [load, t.crisis])

  const call = async (fn) => { setError(''); try { setC(await fn()); onChange?.() } catch (e) { setError(e.message) } }
  const toggle = (active) => {
    const reason = window.prompt(active ? 'Motif de l\'ouverture du mode crise' : 'Motif de la clôture de la crise')
    if (!reason) return
    call(() => api(`/tickets/${enc}/crisis`, { method: 'POST', json: { active, reason } }))
  }
  const add = (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    const due = fd.get('due_at')
    call(() => api(`/tickets/${enc}/crisis/entries`, { method: 'POST', json: { kind, body: fd.get('body'), owner: fd.get('owner') || null, due_at: due ? new Date(due).toISOString() : null } }))
    e.target.reset()
  }
  if (!c) return error ? <p className="error" role="alert">{error}</p> : null
  if (!c.active) {
    return open ? (
      <section className="card section" aria-label="Mode crise">
        <header className="section-head"><h2>Mode crise</h2><button type="button" className="danger" onClick={() => toggle(true)}>Ouvrir le mode crise</button></header>
        <p className="muted small">Active le registre des décisions, le plan d'action et la synthèse de crise (PRIS VI.5.5.1).</p>
        {error && <p className="error" role="alert">{error}</p>}
      </section>
    ) : null
  }
  return (
    <section className="card section crisis" aria-label="Mode crise">
      <header className="section-head">
        <h2>Mode crise <span className="pill danger">ACTIF depuis {formatUtc(c.started_at)}</span></h2>
        {isManager && <button type="button" onClick={() => toggle(false)}>Clore la crise</button>}
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      {Object.entries(KINDS).map(([k, label]) => (
        <div key={k}>
          <h3>{label}</h3>
          {c.items.filter((e) => e.kind === k).length === 0 && <p className="muted small">Aucune entrée.</p>}
          <ul className="crisis-list">
            {c.items.filter((e) => e.kind === k).map((e) => (
              <li key={e.id} className={e.done ? 'done' : ''}>
                {k === 'action' && (
                  <input type="checkbox" checked={e.done} aria-label={`Action faite : ${e.body}`}
                    onChange={(ev) => call(() => api(`/tickets/${enc}/crisis/entries/${e.id}`, { method: 'PATCH', json: { done: ev.target.checked } }))} />
                )}
                <div><span className="crisis-text">{e.body}</span>
                  <span className="muted small"> — {e.created_by}, {formatUtc(e.created_at)}{e.owner ? ` · responsable : ${e.owner}` : ''}{e.due_at ? ` · échéance ${formatUtc(e.due_at)}` : ''}</span></div>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {open && (
        <form className="subform" onSubmit={add}>
          <div className="grid2">
            <label>Type<select value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            {kind === 'action' && <label>Responsable<input name="owner" maxLength={120} /></label>}
          </div>
          {kind === 'action' && <label>Échéance<input type="datetime-local" name="due_at" /></label>}
          <label>Contenu<textarea name="body" required maxLength={5000} rows={3} /></label>
          <div className="row end"><button className="primary">Ajouter au registre</button></div>
        </form>
      )}
    </section>
  )
}
