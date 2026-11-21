import { t as tr } from '../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { utcInputToIso } from '../dates.js'
import { formatUtc } from '../labels.js'
import { useConfirm } from './Confirm.jsx'

const KINDS = { decision: tr('Décisions'), action: tr("Plan d'action"), synthese: tr('Synthèse de crise') }

// Registre de crise d'un ticket. [PRIS VI.5.5.1] Texte brut : jamais interprété comme du HTML.
export default function Crisis({ t, enc, isManager, open, onChange }) {
  const [c, setC] = useState(null)
  const [error, setError] = useState('')
  const [kind, setKind] = useState('decision')
  const load = useCallback(() => api(`/tickets/${enc}/crisis`).then(setC).catch((e) => setError(e.message)), [enc])
  useEffect(() => { load() }, [load, t.crisis])

  const call = async (fn) => { setError(''); try { setC(await fn()); onChange?.(); return true } catch (e) { setError(e.message); return false } }
  const [ask, dialog] = useConfirm()
  const toggle = async (active) => {
    setError('')
    const r = await ask({
      title: active ? tr('Ouvrir le mode crise sur {ref} ?', { ref: t.ref }) : tr('Clore la crise sur {ref} ?', { ref: t.ref }),
      body: <p>{active
        ? tr("Le ticket est signalé « CRISE » dans la file et sur la fiche ; les décisions, le plan d'action et la synthèse de crise sont consignés dans un registre dédié. L'ouverture et son motif sont tracés.")
        : tr("Le ticket n'est plus signalé « CRISE » et le registre de crise n'accepte plus d'entrée. La clôture et son motif sont tracés.")}</p>,
      fields: [{ name: 'reason', label: active ? tr('Motif de l\'ouverture du mode crise') : tr('Motif de la clôture de la crise'), minLength: 3, maxLength: 500 }],
      confirm: active ? tr('Ouvrir le mode crise') : tr('Clore la crise'), danger: active,
      action: ({ reason }) => api(`/tickets/${enc}/crisis`, { method: 'POST', json: { active, reason } }),
    })
    if (r) { setC(r.result); onChange?.() }
  }
  const add = async (e) => {
    e.preventDefault()
    const form = e.target
    const fd = new FormData(form)
    const due = fd.get('due_at')
    // Le formulaire n'est vidé qu'après succès : en cas de refus, la saisie reste à l'écran.
    if (await call(() => api(`/tickets/${enc}/crisis/entries`, { method: 'POST', json: { kind, body: fd.get('body'), owner: fd.get('owner') || null, due_at: utcInputToIso(due) } }))) form.reset()
  }
  if (!c) return error ? <p className="error" role="alert">{error}</p> : null
  if (!c.active) {
    return open ? (
      <section className="card section" aria-label={tr("Mode crise")}>
        <header className="section-head"><h2>{tr("Mode crise")}</h2><button type="button" className="danger" onClick={() => toggle(true)}>{tr("Ouvrir le mode crise")}</button></header>
        <p className="muted small">{tr("Active le registre des décisions, le plan d'action et la synthèse de crise (PRIS VI.5.5.1).")}</p>
        {error && <p className="error" role="alert">{error}</p>}
        {dialog}
      </section>
    ) : null
  }
  return (
    <section className="card section crisis" aria-label={tr("Mode crise")}>
      <header className="section-head">
        <h2>{tr("Mode crise")} <span className="pill danger">{tr('ACTIF depuis {when}', { when: formatUtc(c.started_at) })}</span></h2>
        {isManager && <button type="button" onClick={() => toggle(false)}>{tr("Clore la crise")}</button>}
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      {Object.entries(KINDS).map(([k, label]) => (
        <div key={k}>
          <h3>{label}</h3>
          {c.items.filter((e) => e.kind === k).length === 0 && <p className="muted small">{tr("Aucune entrée.")}</p>}
          <ul className="crisis-list">
            {c.items.filter((e) => e.kind === k).map((e) => (
              <li key={e.id} className={e.done ? 'done' : ''}>
                {k === 'action' && (
                  <input type="checkbox" checked={e.done} aria-label={tr('Action faite : {x}', { x: e.body })}
                    onChange={(ev) => call(() => api(`/tickets/${enc}/crisis/entries/${e.id}`, { method: 'PATCH', json: { done: ev.target.checked } }))} />
                )}
                <div><span className="crisis-text">{e.body}</span>
                  <span className="muted small"> — {e.created_by}, {formatUtc(e.created_at)}{e.owner ? tr(' · responsable : {x}', { x: e.owner }) : ''}{e.due_at ? tr(' · échéance {when}', { when: formatUtc(e.due_at) }) : ''}</span></div>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {open && (
        <form className="subform" onSubmit={add}>
          <div className="grid2">
            <label>{tr("Type")}<select value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            {kind === 'action' && <label>{tr("Responsable")}<input name="owner" maxLength={120} /></label>}
          </div>
          {kind === 'action' && <label>{tr("Échéance (UTC)")}<input type="datetime-local" name="due_at" /></label>}
          <label>{tr("Contenu")}<textarea name="body" required maxLength={5000} rows={3} /></label>
          <div className="row end"><button className="primary">{tr("Ajouter au registre")}</button></div>
        </form>
      )}
      {dialog}
    </section>
  )
}
