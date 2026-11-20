import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'

export default function Mitre() {
  const [items, setItems] = useState(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const load = useCallback(() => api('/mitre/mappings').then((r) => setItems(r.items)).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])
  const add = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    const scope = fd.get('scope')
    setError('')
    try {
      await api('/mitre/mappings', { method: 'POST', json: { technique: fd.get('technique'), name: fd.get('name'), tactic: fd.get('tactic'),
        rule_id: scope === 'rule' ? fd.get('target') : null, rule_group: scope === 'group' ? fd.get('target') : null } })
      e.target.reset(); load()
    } catch (err) { setError(err.message) }
  }
  const importStix = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setError(''); setMsg('')
    const form = new FormData(); form.append('file', file)
    try { const r = await api('/mitre/import', { method: 'POST', form }); setMsg(`${r.added} technique(s) ajoutée(s), ${r.updated} mise(s) à jour (${r.total} au total).`) } catch (err) { setError(err.message) }
  }
  const remove = async (m) => {
    if (!window.confirm(`Supprimer la correspondance ${m.technique} ?`)) return
    try { await api(`/mitre/mappings/${m.id}`, { method: 'DELETE' }); load() } catch (err) { setError(err.message) }
  }
  return (
    <section className="card section" aria-label="Table MITRE">
      <header className="section-head"><h2>Table de correspondance MITRE ATT&amp;CK</h2></header>
      <p className="muted small">Utilisée quand Wazuh ne fournit pas la technique : d'abord l'identifiant de règle, puis le groupe de règles.</p>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      <div className="subform">
        <label>Importer le référentiel ATT&amp;CK (fichier STIX 2.1, par exemple enterprise-attack.json téléchargé hors de Keryx)
          <input type="file" accept=".json,application/json" onChange={importStix} /></label>
        <p className="muted small">Fournit le nom et les tactiques des techniques corrigées à la main. Aucune connexion sortante : le fichier est déposé ici.</p>
      </div>
      <form className="row gap wrap" onSubmit={add}>
        <label>Type<select name="scope"><option value="group">Groupe de règles</option><option value="rule">Identifiant de règle</option></select></label>
        <label>Valeur<input name="target" required placeholder="authentication_failures" /></label>
        <label>Technique<input name="technique" required placeholder="T1110" /></label>
        <label>Nom<input name="name" placeholder="Brute Force" /></label>
        <label>Tactique<input name="tactic" placeholder="Credential Access" /></label>
        <button className="primary" style={{ marginBottom: 10 }}>Ajouter</button>
      </form>
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">Règle / groupe</th><th scope="col">Technique</th><th scope="col">Nom</th><th scope="col">Tactique</th><th scope="col">Ajoutée par</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {items === null && <tr><td colSpan="6" className="muted">Chargement…</td></tr>}
          {items?.length === 0 && <tr><td colSpan="6" className="muted">Aucune correspondance.</td></tr>}
          {items?.map((m) => (
            <tr key={m.id}><td className="mono small">{m.rule_id ? `règle ${m.rule_id}` : `groupe ${m.rule_group}`}</td>
              <td className="mono">{m.technique}</td><td>{m.name}</td><td>{m.tactic}</td><td className="small">{m.created_by}</td>
              <td><button type="button" className="small-btn danger" onClick={() => remove(m)}>Supprimer</button></td></tr>
          ))}
        </tbody>
      </table></div>
    </section>
  )
}
