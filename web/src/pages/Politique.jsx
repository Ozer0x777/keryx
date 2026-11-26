import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ActionStatus, useActionStatus } from '../components/ActionStatus.jsx'
import { t as tr } from '../i18n.js'
import { TLPS } from '../labels.js'

// Politique des clients (ADR-0033), réglée par le manager pour chacun de ses clients : TLP plancher. Les tickets et
// les pièces naissent à ce niveau ; un analyste ne peut pas descendre en dessous. Relever le plancher relève les
// tickets ouverts qui sont en dessous ; le baisser ne baisse aucun ticket.
function Client({ c, onSaved }) {
  const [plancher, setPlancher] = useState(c.tlp_plancher || '')
  const [status, track, setStatus] = useActionStatus()
  const changed = plancher !== (c.tlp_plancher || '')
  const save = async () => {
    const r = await track(() => api(`/politique/${encodeURIComponent(c.key)}`, { method: 'PUT', json: { tlp_plancher: plancher || null } }))
    if (!r) return
    onSaved(r)
    setStatus({ ok: r.tickets_releves.length
      ? tr('Enregistré : {n} ticket(s) ouvert(s) relevé(s) au plancher.', { n: r.tickets_releves.length })
      : tr('Enregistré.') })
  }
  return (
    <section className="card section" aria-label={c.name}>
      <header className="section-head"><h2><span className="mono">{c.key}</span> · {c.name}</h2></header>
      <div className="section-body">
        <div className="row wrap gap">
          <label>{tr('TLP plancher')}
            <select value={plancher} aria-describedby={`plancher-${c.key}`} onChange={(e) => setPlancher(e.target.value)}>
              <option value="">{tr('Aucun (tickets en TLP:AMBER, sans plancher)')}</option>
              {TLPS.map((x) => <option key={x} value={x}>{x}</option>)}
            </select>
          </label>
          <button type="button" className="primary" onClick={save} disabled={!changed}>{tr('Enregistrer')}</button>
        </div>
        <p className="field-hint" id={`plancher-${c.key}`}>{tr("Les nouveaux tickets et pièces de ce client naissent à ce niveau. Un analyste peut monter, jamais descendre en dessous ; un manager peut descendre un ticket en dessous avec un motif. Relever le plancher relève les tickets ouverts qui sont en dessous ; le baisser ne baisse aucun ticket.")}</p>
        <ActionStatus state={status} />
      </div>
    </section>
  )
}

export default function Politique() {
  const [items, setItems] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/politique').then((r) => setItems(r.items)).catch((e) => setError(e.message)) }, [])
  return (
    <>
      <header className="page-head"><div>
        <h1>{tr('Politique des clients')}</h1>
        <p className="muted">{tr('Règles appliquées aux tickets de chacun de vos clients. Chaque modification est inscrite au journal d’audit.')}</p>
      </div></header>
      {error && <p className="error" role="alert">{error}</p>}
      {items === null && !error && <p className="loading">{tr('Chargement…')}</p>}
      {items?.map((c) => (
        <Client key={c.key} c={c} onSaved={(r) => setItems((xs) => xs.map((x) => (x.key === r.key ? { ...x, tlp_plancher: r.tlp_plancher } : x)))} />
      ))}
    </>
  )
}
