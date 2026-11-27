import { useEffect, useState } from 'react'
import { api, downloadBlob } from '../api.js'
import { t as tr } from '../i18n.js'
import { ActionStatus, useActionStatus } from './ActionStatus.jsx'
import Section from './Section.jsx'
import { UnsavedBadge, useUnsaved } from './Unsaved.jsx'

const AXIS_TITLES = {
  who_why: 'Qui et/ou pourquoi', what: 'Quoi', how: 'Comment', status: 'Statut de l\'incident', vulnerability: 'Vulnérabilité(s) exploitée(s)',
  asset: 'Type de cible', cia: 'Conséquence (C-I-D)', impact: "Type d'impact",
}

// Classification ETSI GS ISI 002 (clause 4.4 et Annexe B). Les intitulés des listes sont ceux, anglais, de la norme.
// Forme comparable d'une classification : clés triées, valeurs vides retirées (un choix remis à « — » n'est pas une modification).
function canon(o) {
  const clean = (x) => {
    if (Array.isArray(x)) return x.length ? [...x].sort() : undefined
    if (x && typeof x === 'object') {
      const out = Object.fromEntries(Object.keys(x).sort().map((k) => [k, clean(x[k])]).filter(([, y]) => y !== undefined))
      return Object.keys(out).length ? out : undefined
    }
    return x === '' || x === null || x === undefined ? undefined : x
  }
  return JSON.stringify(clean(o) ?? {})
}

export default function IsiPanel({ t, enc, run, open }) {
  const [dict, setDict] = useState(null)
  const [v, setV] = useState(t.isi || {})
  const [status, track] = useActionStatus()
  useEffect(() => { api('/isi/dictionary').then(setDict).catch(() => {}) }, [])
  // Le ticket est rechargé après chaque action (nouvel objet à chaque fois) : la saisie en cours n'est remplacée que si
  // la classification enregistrée a réellement changé, pas à chaque rechargement.
  const saved = JSON.stringify(t.isi || {})
  useEffect(() => { setV(JSON.parse(saved)) }, [saved])
  const isiDirty = open && canon(v) !== canon(t.isi || {})
  useUnsaved('isi', tr('classification ISI'), isiDirty)
  if (!dict) return null
  const set = (k, val) => setV((x) => ({ ...x, [k]: val }))
  const setDetail = (k, val) => setV((x) => ({ ...x, detail: { ...(x.detail || {}), [k]: val } }))
  const toggleVuln = (code) => setV((x) => {
    const cur = x.vulnerability || []
    const next = cur.includes(code) ? cur.filter((c) => c !== code) : [...cur, code].slice(0, 3)
    return { ...x, vulnerability: next }
  })
  const save = () => track(() => run(() => api(`/tickets/${enc}/isi`, { method: 'PUT', json: v }), tr('Classification ETSI ISI enregistrée.')))
  const exportDoc = () => track(async () => {
    downloadBlob(new Blob([JSON.stringify(await api(`/tickets/${enc}/isi/iodef`), null, 2)], { type: 'application/json' }), `${t.ref}-etsi-isi.json`)
  }, tr('Export téléchargé.'))
  const select = (axis, options) => (
    <label key={axis}>{tr(AXIS_TITLES[axis])}{dict.mandatory.includes(axis) ? ' *' : ''}
      <select value={v[axis] || ''} disabled={!open} onChange={(e) => set(axis, e.target.value || undefined)}>
        <option value="">—</option>
        {options.map((o) => <option key={o.code} value={o.code}>{o.ref} — {o.label}</option>)}
      </select>
      {v[axis] && <input aria-label={`${tr(AXIS_TITLES[axis])} : ${tr('précision')}`} placeholder={tr('Précision (Annexe B, sous-liste)')} maxLength={200} disabled={!open}
        value={v.detail?.[axis] || ''} onChange={(e) => setDetail(axis, e.target.value)} />}
    </label>
  )
  return (
    <Section id="isi" filled={Boolean(t.isi?.category)} title={tr('Classification ETSI ISI')} summary={<>{t.isi?.category ? <span className="mono">{t.isi.category}</span> : tr('à compléter')}<UnsavedBadge show={isiDirty} /></>}>
      <p className="muted small">{tr("ETSI GS ISI 002 : les axes marqués * sont obligatoires pour exporter.")}</p>
      <label>{tr('Catégorie')}
        <select value={v.category || ''} disabled={!open} onChange={(e) => set('category', e.target.value || undefined)}>
          <option value="">—</option>
          {Object.entries(dict.categories).map(([k, l]) => <option key={k} value={k}>{k} — {tr(l)}</option>)}
        </select>
      </label>
      {select('who_why', dict.axes.who_why)}
      {select('what', dict.axes.what)}
      {select('how', dict.how)}
      {select('status', dict.axes.status)}
      <fieldset className="fieldset"><legend>{tr(AXIS_TITLES.vulnerability)} ({tr('3 au plus')})</legend>
        {dict.axes.vulnerability.map((o) => (
          <label key={o.code} className="check"><input type="checkbox" disabled={!open} checked={(v.vulnerability || []).includes(o.code)} onChange={() => toggleVuln(o.code)} /> {o.ref} — {o.label}</label>
        ))}
      </fieldset>
      {select('asset', dict.axes.asset)}
      {select('cia', dict.axes.cia)}
      {select('impact', dict.axes.impact)}
      <div className="row gap wrap">
        {open && <button type="button" className="primary" onClick={save}>{tr('Enregistrer')}</button>}
        <button type="button" onClick={exportDoc}>{tr('Exporter (IODEF 2.0, ETSI ISI)')}</button>
      </div>
      <ActionStatus state={status} />
    </Section>
  )
}
