import { t as tr } from '../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { utcInputToIso } from '../dates.js'
import { formatUtc } from '../labels.js'
import { useConfirm } from './Confirm.jsx'
import { UnsavedBadge, useUnsaved } from './Unsaved.jsx'

// PRIS VI.5.5.1 : arbitrages, objectifs stratégiques déclinés en actions (objectifs opérationnels avec délai), synthèse
// de la situation, critères de sortie de crise (VI.3.g), dérogations et leurs risques (d.iii).
const KINDS = { decision: tr('Décisions (arbitrages)'), objectif: tr('Objectifs stratégiques'), action: tr("Plan d'action (objectifs opérationnels)"), synthese: tr('Synthèse de crise'), critere_sortie: tr('Critères de sortie de crise'), derogation: tr('Dérogations') }
const COCHABLES = ['objectif', 'action', 'critere_sortie']

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
  // Formulaire d'entrée non contrôlé : « modifié » dès qu'un champ texte est rempli, remis à zéro après l'ajout.
  const [entryDirty, setEntryDirty] = useState(false)
  useUnsaved('crise', tr('entrée de crise'), open && entryDirty)
  const onEntryInput = (e) => {
    const fd = new FormData(e.currentTarget)
    setEntryDirty(['body', 'owner', 'due_at'].some((k) => String(fd.get(k) || '').trim()))
  }
  const add = async (e) => {
    e.preventDefault()
    const form = e.target
    const fd = new FormData(form)
    const due = fd.get('due_at')
    // Le formulaire n'est vidé qu'après succès : en cas de refus, la saisie reste à l'écran.
    const json = { kind, body: fd.get('body'), owner: fd.get('owner') || null, due_at: utcInputToIso(due),
      parent_id: fd.get('parent_id') || null, decision_id: fd.get('decision_id') || null, entite: fd.get('entite') || null, risque: fd.get('risque') || null }
    if (await call(() => api(`/tickets/${enc}/crisis/entries`, { method: 'POST', json }))) { form.reset(); setEntryDirty(false) }
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
                {COCHABLES.includes(k) && (
                  <input type="checkbox" checked={e.done} aria-label={k === 'critere_sortie' ? tr('Critère atteint : {x}', { x: e.body }) : tr('Action faite : {x}', { x: e.body })}
                    onChange={(ev) => call(() => api(`/tickets/${enc}/crisis/entries/${e.id}`, { method: 'PATCH', json: { done: ev.target.checked } }))} />
                )}
                <div><span className="crisis-text">{e.body}</span>
                  <span className="muted small"> — {e.created_by}, {formatUtc(e.created_at)}{e.owner ? tr(' · responsable : {x}', { x: e.owner }) : ''}{e.due_at ? tr(' · échéance {when}', { when: formatUtc(e.due_at) }) : ''}
                    {e.entite ? tr(' · arbitrage : {x}', { x: e.entite }) : ''}
                    {e.parent_id ? tr(' · objectif : {x}', { x: c.items.find((y) => y.id === e.parent_id)?.body || '?' }) : ''}
                    {e.decision_id ? tr(' · décision : {x}', { x: c.items.find((y) => y.id === e.decision_id)?.body || '?' }) : ''}
                    {e.valide_par ? tr(' · validé par {who} le {when}', { who: e.valide_par, when: formatUtc(e.valide_le) }) : ''}</span>
                  {e.risque && <div className="small">{tr('Risque associé : {x}', { x: e.risque })}</div>}
                  {open && ['objectif', 'action'].includes(k) && !e.valide_par && (
                    <button type="button" className="small" onClick={async () => {
                      const r = await ask({ title: tr('Validation par la cellule de crise stratégique'), fields: [{ name: 'valide_par', label: tr('Validé par'), minLength: 2, maxLength: 200 }],
                        confirm: tr('Enregistrer la validation'), action: ({ valide_par }) => api(`/tickets/${enc}/crisis/entries/${e.id}`, { method: 'PATCH', json: { valide_par } }) })
                      if (r) { setC(r.result); onChange?.() }
                    }}>{tr('Valider')}</button>)}</div>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {open && (
        <form className="subform" onSubmit={add} onInput={onEntryInput}>
          <UnsavedBadge show={entryDirty} />
          <div className="grid2">
            <label>{tr("Type")}<select value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            {kind === 'action' && <label>{tr("Responsable")}<input name="owner" maxLength={120} /></label>}
          </div>
          {kind === 'action' && <label>{tr("Échéance (UTC)")}<input type="datetime-local" name="due_at" /></label>}
          {kind === 'action' && (
            <div className="grid2">
              <label>{tr('Objectif stratégique')}<select name="parent_id" defaultValue=""><option value="">{tr('Aucun')}</option>
                {c.items.filter((y) => y.kind === 'objectif').map((y) => <option key={y.id} value={y.id}>{y.body.slice(0, 80)}</option>)}</select></label>
              <label>{tr("Arbitrage qui l'a permise")}<select name="decision_id" defaultValue=""><option value="">{tr('Aucun')}</option>
                {c.items.filter((y) => y.kind === 'decision').map((y) => <option key={y.id} value={y.id}>{y.body.slice(0, 80)}</option>)}</select></label>
            </div>)}
          {kind === 'decision' && <label>{tr("Entité responsable de l'arbitrage")}<input name="entite" maxLength={200} /></label>}
          {kind === 'derogation' && <label>{tr('Risque associé')}<textarea name="risque" maxLength={5000} rows={2} /></label>}
          <label>{tr("Contenu")}<textarea name="body" required maxLength={5000} rows={3} /></label>
          <div className="row end"><button className="primary">{tr("Ajouter au registre")}</button></div>
        </form>
      )}
      {dialog}
    </section>
  )
}
