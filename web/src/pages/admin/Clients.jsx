import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import { DOMMAGES, IMPORTANCES } from '../../labels.js'

const SEVS = ['Faible', 'Moyenne', 'Élevée', 'Critique']
const DEFAULT_GRID = {
  limites: { standard: 'Faible', sensible: 'Moyenne', vital: 'Élevée' },
  significatifs: { standard: 'Moyenne', sensible: 'Élevée', vital: 'Critique' },
  graves: { standard: 'Élevée', sensible: 'Critique', vital: 'Critique' },
}

function ClientEditor({ client, onSaved, onError }) {
  const [emails, setEmails] = useState((client.contact_emails || []).join(', '))
  const [retention, setRetention] = useState(client.retention_months ?? '')
  const [maxMb, setMaxMb] = useState(client.max_attachment_mb ?? '')
  const [grid, setGrid] = useState(client.severity_grid || null)
  const [sla, setSla] = useState(client.sla || {})
  const g = grid || DEFAULT_GRID
  const save = async (e) => {
    e.preventDefault()
    const cleanSla = Object.fromEntries(Object.entries(sla).filter(([, v]) => v.qualification || v.resolution)
      .map(([k, v]) => [k, Object.fromEntries(Object.entries(v).filter(([, h]) => h).map(([a, h]) => [a, Number(h)]))]))
    try {
      await api(`/admin/clients/${client.key}`, { method: 'PATCH', json: {
        contact_emails: emails.split(/[,\s;]+/).filter(Boolean),
        retention_months: retention === '' ? null : Number(retention),
        max_attachment_mb: maxMb === '' ? null : Number(maxMb),
        severity_grid: grid, sla: Object.keys(cleanSla).length ? cleanSla : null } })
      onSaved()
    } catch (err) { onError(err.message) }
  }
  return (
    <form className="subform" onSubmit={save}>
      <label>Contacts de notification (séparés par des virgules)<input value={emails} onChange={(e) => setEmails(e.target.value)} /></label>
      <label>Rétention des alertes brutes, en mois (6 minimum, vide = valeur par défaut)<input type="number" min="6" max="120" value={retention} onChange={(e) => setRetention(e.target.value)} /></label>
      <label>Taille maximale d'une pièce, en Mo (1 à 20, vide = 20 : plafond fixé par le plan)<input type="number" min="1" max="20" value={maxMb} onChange={(e) => setMaxMb(e.target.value)} /></label>
      <h3>Grille de gravité {grid ? '(propre au client)' : '(grille par défaut)'}</h3>
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">Dommages \ Importance</th>{Object.entries(IMPORTANCES).map(([k, v]) => <th key={k} scope="col">{v}</th>)}</tr></thead>
        <tbody>{Object.entries(DOMMAGES).map(([d, dl]) => (
          <tr key={d}><th scope="row">{dl}</th>{Object.keys(IMPORTANCES).map((i) => (
            <td key={i}><select aria-label={`${dl}, ${IMPORTANCES[i]}`} value={g[d][i]}
              onChange={(e) => setGrid({ ...g, [d]: { ...g[d], [i]: e.target.value } })}>
              {SEVS.map((s) => <option key={s}>{s}</option>)}</select></td>))}</tr>))}
        </tbody></table></div>
      {grid && <button type="button" className="link" onClick={() => setGrid(null)}>Revenir à la grille par défaut</button>}
      <h3>Délais cibles (heures)</h3>
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">Gravité</th><th scope="col">Qualification</th><th scope="col">Résolution</th></tr></thead>
        <tbody>{SEVS.map((s) => (
          <tr key={s}><th scope="row">{s}</th>{['qualification', 'resolution'].map((k) => (
            <td key={k}><input type="number" min="0" step="0.5" aria-label={`${s}, ${k}`} value={sla[s]?.[k] ?? ''}
              onChange={(e) => setSla({ ...sla, [s]: { ...sla[s], [k]: e.target.value } })} /></td>))}</tr>))}
        </tbody></table></div>
      <div className="row gap end"><button className="primary">Enregistrer</button></div>
    </form>
  )
}

export default function Clients() {
  const [items, setItems] = useState(null)
  const [open, setOpen] = useState(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const load = useCallback(() => api('/admin/clients').then((r) => setItems(r.items)).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])
  const create = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    setError('')
    try { await api('/admin/clients', { method: 'POST', json: { key: fd.get('key'), name: fd.get('name') } }); e.target.reset(); setMsg('Client créé.'); load() } catch (err) { setError(err.message) }
  }
  return (
    <section className="card section" aria-label="Clients">
      <header className="section-head"><h2>Clients</h2></header>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      <form className="row gap wrap" onSubmit={create}>
        <label>Clé (ex. ACME)<input name="key" required pattern="[A-Za-z0-9]{1,16}" /></label>
        <label className="grow">Nom<input name="name" required /></label>
        <button className="primary">Ajouter</button>
      </form>
      {items?.map((c) => (
        <div key={c.key} className="client-block">
          <div className="row between wrap">
            <div><span className="mono strong">{c.key}</span> — {c.name} <span className="muted small">({c.tickets} ticket{c.tickets > 1 ? 's' : ''})</span></div>
            <button type="button" className="small-btn" aria-expanded={open === c.key} onClick={() => setOpen(open === c.key ? null : c.key)}>{open === c.key ? 'Fermer' : 'Paramétrer'}</button>
          </div>
          {open === c.key && <ClientEditor client={c} onSaved={() => { setMsg('Client enregistré.'); load() }} onError={setError} />}
        </div>
      ))}
    </section>
  )
}
