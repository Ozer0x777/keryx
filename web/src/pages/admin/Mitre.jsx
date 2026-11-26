import { t as tr } from '../../i18n.js'
import { useLocalList } from '../../components/LocalList.jsx'

const texteMitre = (m) => [m.rule_id, m.rule_group, m.technique, m.name, m.tactic, m.created_by].filter(Boolean).join(' ')
import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import { useConfirm } from '../../components/Confirm.jsx'

export default function Mitre() {
  const [items, setItems] = useState(null)
  const list = useLocalList(items, texteMitre, tr('Pages de la table MITRE'))
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [sugg, setSugg] = useState([])
  const load = useCallback(() => api('/mitre/mappings').then((r) => setItems(r.items)).catch((e) => setError(e.message)), [])
  const loadSugg = useCallback(() => api('/mitre/suggestions').then((r) => setSugg(r.items)).catch(() => setSugg([])), [])
  useEffect(() => { load(); loadSugg() }, [load, loadSugg])
  const accept = async (s) => {
    setError('')
    try { await api('/mitre/mappings', { method: 'POST', json: { technique: s.technique, name: s.name, tactic: s.tactics?.[0] || '', rule_id: s.rule_id } }); load(); loadSugg() } catch (err) { setError(err.message) }
  }
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
    try { const r = await api('/mitre/import', { method: 'POST', form }); setMsg(tr('{a} technique(s) ajoutée(s), {u} mise(s) à jour ({total} au total).', { a: r.added, u: r.updated, total: r.total })) } catch (err) { setError(err.message) }
  }
  const [ask, dialog] = useConfirm()
  const remove = async (m) => {
    const r = await ask({
      title: tr('Supprimer la correspondance {t} ?', { t: `${m.rule_id ? tr('règle {id}', { id: m.rule_id }) : tr('groupe {id}', { id: m.rule_group })} → ${m.technique}` }),
      body: <p>{tr("Les prochaines alertes de cette règle ou de ce groupe ne recevront plus cette technique automatiquement. Les tickets existants ne changent pas.")}</p>,
      confirm: tr('Supprimer la correspondance'), danger: true,
      action: () => api(`/mitre/mappings/${m.id}`, { method: 'DELETE' }),
    })
    if (r) { setError(''); load() }
  }
  return (
    <section className="card section" aria-label={tr("Table MITRE")}>
      <header className="section-head"><h2>{tr("Table de correspondance MITRE ATT&CK")}</h2></header>
      <p className="muted small">{tr("Utilisée quand Wazuh ne fournit pas la technique : d'abord l'identifiant de règle, puis le groupe de règles.")}</p>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {sugg.length > 0 && (
        <div className="subform" role="region" aria-label={tr("Propositions")}>
          <h3 style={{ marginTop: 0 }}>{tr("Propositions")}</h3>
          <p className="muted small">{tr("Ces techniques ont été ajoutées à la main sur plusieurs tickets de la même règle. Les ajouter à la table évite de les saisir à chaque fois.")}</p>
          <ul className="found">{sugg.map((s) => (
            <li key={s.rule_id + s.technique}>{tr("règle")} <span className="mono">{s.rule_id}</span>{s.rule_description ? ` (${s.rule_description})` : ''} → <span className="mono">{s.technique}</span> {s.name} · {tr('{n} correction(s)', { n: s.count })}
              {' '}<button type="button" className="small-btn" onClick={() => accept(s)}>{tr("Ajouter à la table")}</button></li>))}</ul>
        </div>
      )}
      <div className="subform">
        <label>{tr('Importer le référentiel ATT&CK (fichier STIX 2.1, par exemple enterprise-attack.json téléchargé hors de Keryx)')}
          <input type="file" accept=".json,application/json" onChange={importStix} /></label>
        <p className="muted small">{tr("Fournit le nom et les tactiques des techniques corrigées à la main. Aucune connexion sortante : le fichier est déposé ici.")}</p>
      </div>
      <form className="row gap wrap" onSubmit={add}>
        <label>{tr("Type")}<select name="scope"><option value="group">{tr("Groupe de règles")}</option><option value="rule">{tr("Identifiant de règle")}</option></select></label>
        <label>{tr("Valeur")}<input name="target" required placeholder={tr("authentication_failures")} /></label>
        <label>{tr("Technique")}<input name="technique" required placeholder="T1110" /></label>
        <label>{tr("Nom")}<input name="name" placeholder={tr("Brute Force")} /></label>
        <label>{tr("Tactique")}<input name="tactic" placeholder={tr("Credential Access")} /></label>
        <button className="primary">{tr("Ajouter")}</button>
      </form>
      {list.search}
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">{tr("Règle / groupe")}</th><th scope="col">{tr("Technique")}</th><th scope="col">{tr("Nom")}</th><th scope="col">{tr("Tactique")}</th><th scope="col">{tr("Ajoutée par")}</th><th scope="col"><span className="sr-only">{tr("Actions")}</span></th></tr></thead>
        <tbody>
          {items === null && <tr><td colSpan="6" className="muted">{tr("Chargement…")}</td></tr>}
          {items?.length === 0 && <tr><td colSpan="6" className="muted">{tr("Aucune correspondance.")}</td></tr>}
          {list.rows?.map((m) => (
            <tr key={m.id}><td className="mono small">{m.rule_id ? tr('règle {id}', { id: m.rule_id }) : tr('groupe {id}', { id: m.rule_group })}</td>
              <td className="mono">{m.technique}</td><td>{m.name}</td><td>{m.tactic}</td><td className="small">{m.created_by}</td>
              <td><button type="button" className="small-btn danger" onClick={() => remove(m)}>{tr("Supprimer")}</button></td></tr>
          ))}
        </tbody>
      </table></div>
      {list.empty}
      {list.pager}
      {dialog}
    </section>
  )
}
