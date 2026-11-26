import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { ActionStatus, useActionStatus } from '../components/ActionStatus.jsx'
import { t as tr } from '../i18n.js'
import { TLPS } from '../labels.js'

// Politique des clients, réglée par le manager pour chacun de ses clients :
// - TLP plancher (ADR-0033) : les tickets et les pièces naissent à ce niveau ; un analyste ne peut pas descendre en
//   dessous. Relever le plancher relève les tickets ouverts qui sont en dessous ; le baisser ne baisse aucun ticket.
// - Astreinte (ADR-0032) : criticités qui préviennent le canal d'astreinte, délai avant escalade, canaux choisis parmi
//   ceux que l'Admin a déclarés ; délai d'acquittement dans le rapport remis au client.
const CRITICITES = ['Critique', 'Élevée', 'Moyenne', 'Faible']

function Client({ c, canaux, onSaved }) {
  const [plancher, setPlancher] = useState(c.tlp_plancher || '')
  const [rapport, setRapport] = useState(Boolean(c.acquittement_rapport))
  const [ast, setAst] = useState(c.astreinte)
  const [status, track, setStatus] = useActionStatus()
  const changed = plancher !== (c.tlp_plancher || '') || rapport !== Boolean(c.acquittement_rapport)
    || JSON.stringify(ast) !== JSON.stringify(c.astreinte)
  const set = (patch) => setAst((a) => ({ ...a, ...patch }))
  const crit = (x, on) => set({ criticites: CRITICITES.filter((k) => (k === x ? on : ast.criticites.includes(k))) })
  const save = async () => {
    const json = {
      tlp_plancher: plancher || null, acquittement_rapport: rapport,
      astreinte_active: ast.active, astreinte_criticites: ast.criticites, astreinte_delais: ast.delais,
      astreinte_canal_id: ast.canal_id || null, escalade_canal_id: ast.escalade_canal_id || null,
    }
    const r = await track(() => api(`/politique/${encodeURIComponent(c.key)}`, { method: 'PUT', json }))
    if (!r) return
    onSaved(r)
    setAst(r.astreinte)
    setStatus({ ok: r.tickets_releves.length
      ? tr('Enregistré : {n} ticket(s) ouvert(s) relevé(s) au plancher.', { n: r.tickets_releves.length })
      : tr('Enregistré.') })
  }
  const id = (x) => `${x}-${c.key}`
  return (
    <section className="card section" aria-label={c.name}>
      <header className="section-head"><h2><span className="mono">{c.key}</span> · {c.name}</h2></header>
      <div className="section-body stack">
        <h3>{tr('Marquage')}</h3>
        <label>{tr('TLP plancher')}
          <select value={plancher} aria-describedby={id('plancher')} onChange={(e) => setPlancher(e.target.value)}>
            <option value="">{tr('Aucun (tickets en TLP:AMBER, sans plancher)')}</option>
            {TLPS.map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <p className="field-hint" id={id('plancher')}>{tr("Les nouveaux tickets et pièces de ce client naissent à ce niveau. Un analyste peut monter, jamais descendre en dessous ; un manager peut descendre un ticket en dessous avec un motif. Relever le plancher relève les tickets ouverts qui sont en dessous ; le baisser ne baisse aucun ticket.")}</p>

        <h3>{tr('Astreinte')}</h3>
        {canaux.length === 0
          ? <p className="muted small">{tr("Aucun canal d'astreinte n'est déclaré : l'Admin les ajoute dans Administration > Canaux d'astreinte.")}</p>
          : <>
            <label className="check"><input type="checkbox" checked={ast.active} onChange={(e) => set({ active: e.target.checked })} />{' '}
              {tr("Prévenir l'astreinte à l'ouverture d'un ticket de ce client")}</label>
            <div className="grid2">
              <label>{tr("Canal d'astreinte")}
                <select value={ast.canal_id || ''} onChange={(e) => set({ canal_id: e.target.value || null })}>
                  <option value="">{tr('Aucun')}</option>
                  {canaux.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                </select></label>
              <label>{tr("Canal d'escalade")}
                <select value={ast.escalade_canal_id || ''} onChange={(e) => set({ escalade_canal_id: e.target.value || null })}>
                  <option value="">{tr('Aucun (pas d’escalade)')}</option>
                  {canaux.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                </select></label>
            </div>
            <fieldset>
              <legend>{tr("Criticités qui préviennent l'astreinte, et délai avant escalade sans prise en charge")}</legend>
              <div className="table-wrap" tabIndex={0} role="region" aria-label={tr('Délais d’escalade de {c}', { c: c.name })}><table className="grid">
                <thead><tr><th scope="col">{tr('Criticité')}</th><th scope="col">{tr('Prévient')}</th><th scope="col">{tr('Escalade après (minutes)')}</th></tr></thead>
                <tbody>{CRITICITES.map((k) => (
                  <tr key={k}>
                    <th scope="row">{tr(k)}</th>
                    <td><input type="checkbox" aria-label={tr('{k} : prévenir l’astreinte', { k: tr(k) })} checked={ast.criticites.includes(k)} onChange={(e) => crit(k, e.target.checked)} /></td>
                    <td><input type="number" min={1} max={1440} aria-label={tr('{k} : escalade après (minutes)', { k: tr(k) })} value={ast.delais[k]}
                      onChange={(e) => set({ delais: { ...ast.delais, [k]: Number(e.target.value) || 1 } })} /></td>
                  </tr>
                ))}</tbody>
              </table></div>
            </fieldset>
            <p className="field-hint">{tr("Sans prise en charge, affectation, changement de statut ou qualification dans ce délai, Keryx prévient une fois le canal d'escalade, puis s'arrête. Le message ne contient que la référence, le client, la criticité et le lien, sauf si le canal prévoit le titre.")}</p>
          </>}
        <label className="check"><input type="checkbox" checked={rapport} onChange={(e) => setRapport(e.target.checked)} />{' '}
          {tr("Inclure le délai d'acquittement dans le rapport périodique remis au client")}</label>
        <div><button type="button" className="primary" onClick={save} disabled={!changed}>{tr('Enregistrer')}</button></div>
        <ActionStatus state={status} />
      </div>
    </section>
  )
}

export default function Politique() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/politique').then(setData).catch((e) => setError(e.message)) }, [])
  const saved = (r) => setData((d) => ({ ...d, items: d.items.map((x) => (x.key === r.key ? { ...x, ...r } : x)) }))
  return (
    <>
      <header className="page-head"><div>
        <h1>{tr('Politique des clients')}</h1>
        <p className="muted">{tr('Règles appliquées aux tickets de chacun de vos clients. Chaque modification est inscrite au journal d’audit.')}</p>
      </div></header>
      {error && <p className="error" role="alert">{error}</p>}
      {data === null && !error && <p className="loading">{tr('Chargement…')}</p>}
      {data?.items.map((c) => <Client key={c.key} c={c} canaux={data.canaux} onSaved={saved} />)}
    </>
  )
}
