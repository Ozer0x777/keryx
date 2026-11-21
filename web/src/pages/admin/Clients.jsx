import { t as tr } from '../../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import { ActionStatus, useActionStatus } from '../../components/ActionStatus.jsx'
import { DOMMAGES, IMPORTANCES } from '../../labels.js'

const SEVS = ['Faible', 'Moyenne', 'Élevée', 'Critique']
const DEFAULT_GRID = {
  limites: { standard: 'Faible', sensible: 'Moyenne', vital: 'Élevée' },
  significatifs: { standard: 'Moyenne', sensible: 'Élevée', vital: 'Critique' },
  graves: { standard: 'Élevée', sensible: 'Critique', vital: 'Critique' },
}

// Contexte Wazuh d'un client (ADR-0021) : lien vers l'alerte dans le tableau de bord et lecture de l'indexeur.
// Tout est vide par défaut : la fonction n'apparaît alors nulle part. Le compte de lecture n'est jamais réaffiché
// (l'API ne renvoie qu'un indicateur) : un champ laissé vide le conserve.
function WazuhSettings({ client, v, set }) {
  const id = `wz-${client.key}`
  const state = client.wazuh_context_enabled
    ? tr("lecture de l'indexeur active")
    : client.wazuh_link_enabled ? tr("lien vers l'alerte actif") : tr("désactivé : rien n'est réglé")
  return (
    <>
      <h3>{tr("Contexte Wazuh")} <span className="muted small">({state})</span></h3>
      <p className="muted small">{tr("Réservé aux analystes et aux managers de ce client : jamais montré au client. Laisser vide pour ne pas activer.")}</p>
      <label>{tr("Modèle d'URL de l'alerte dans le tableau de bord Wazuh (HTTPS)")}
        <input className="mono" value={v.dashboard} maxLength={500} spellCheck={false} aria-describedby={`${id}-vars`}
          placeholder="https://wazuh.exemple/app/…{alert_id}…" onChange={(e) => set({ dashboard: e.target.value })} />
      </label>
      <p className="field-hint wz-hint" id={`${id}-vars`}>{tr("Variables remplacées par Keryx : {alert_id} (identifiant Wazuh de l'alerte), {agent_id}, {rule_id}, {timestamp}, {from} et {to} (cinq minutes avant et après l'alerte, UTC), {index_pattern}. L'index réel et l'identifiant interne du document ne sont pas connus de Keryx.")}</p>
      <div className="grid2">
        <label>{tr("Adresse de l'indexeur Wazuh (HTTPS)")}
          <input className="mono" value={v.indexer} maxLength={300} spellCheck={false} placeholder="https://indexeur.exemple:9200"
            aria-describedby={`${id}-url`} onChange={(e) => set({ indexer: e.target.value })} />
        </label>
        <label>{tr("Motif d'index (vide = wazuh-alerts-*)")}
          <input className="mono" value={v.pattern} maxLength={128} spellCheck={false} placeholder="wazuh-alerts-*" onChange={(e) => set({ pattern: e.target.value })} />
        </label>
      </div>
      <p className="field-hint wz-hint" id={`${id}-url`}>{tr("Adresses refusées : boucle locale, lien local, services de métadonnées. Changer l'adresse efface le compte enregistré : il faut le ressaisir.")}</p>
      <div className="grid2">
        <label>{tr("Compte en lecture seule : identifiant")}
          <input value={v.user} maxLength={128} autoComplete="off" spellCheck={false} disabled={v.dropCredentials}
            aria-describedby={`${id}-cred`} onChange={(e) => set({ user: e.target.value })} />
        </label>
        <label>{tr("Compte en lecture seule : mot de passe")}
          <input type="password" value={v.password} maxLength={256} autoComplete="new-password" disabled={v.dropCredentials}
            aria-describedby={`${id}-cred`} onChange={(e) => set({ password: e.target.value })} />
        </label>
      </div>
      <p className="field-hint wz-hint" id={`${id}-cred`}>{client.wazuh_credentials_set
        ? tr("Un compte est enregistré (chiffré) ; il n'est jamais réaffiché. Laisser ces champs vides pour le conserver.")
        : tr("Aucun compte enregistré. Utiliser un compte de l'indexeur limité à la lecture des index de ce client.")}</p>
      {client.wazuh_credentials_set && (
        <label className="check"><input type="checkbox" checked={v.dropCredentials} onChange={(e) => set({ dropCredentials: e.target.checked })} /> {tr("Effacer le compte enregistré")}</label>
      )}
      <label className="check"><input type="checkbox" checked={v.verify} aria-describedby={`${id}-tls`} onChange={(e) => set({ verify: e.target.checked })} /> {tr("Contrôler le certificat TLS de l'indexeur (recommandé)")}</label>
      <p className="field-hint wz-hint" id={`${id}-tls`}>{v.verify
        ? tr("Le certificat doit être émis par l'autorité ci-dessous ou, à défaut, par une autorité connue du système.")
        : tr("Sans contrôle, le compte de lecture peut être intercepté sur le réseau : à réserver à un essai.")}</p>
      <label>{tr("Autorité de certification de l'indexeur (certificat PEM, facultatif)")}
        <textarea className="mono" rows={4} value={v.ca} maxLength={20000} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => set({ ca: e.target.value })} />
      </label>
    </>
  )
}

function ClientEditor({ client, onSaved }) {
  const [emails, setEmails] = useState((client.contact_emails || []).join(', '))
  const [retention, setRetention] = useState(client.retention_months ?? '')
  const [maxMb, setMaxMb] = useState(client.max_attachment_mb ?? '')
  const [grid, setGrid] = useState(client.severity_grid || null)
  const [sla, setSla] = useState(client.sla || {})
  const [wz, setWz] = useState({
    dashboard: client.wazuh_dashboard_url || '', indexer: client.wazuh_indexer_url || '', pattern: client.wazuh_index_pattern || '',
    user: '', password: '', dropCredentials: false, verify: client.wazuh_tls_verify !== false, ca: client.wazuh_ca_pem || '',
  })
  const [status, track] = useActionStatus()
  const g = grid || DEFAULT_GRID
  const save = async (e) => {
    e.preventDefault()
    const cleanSla = Object.fromEntries(Object.entries(sla).filter(([, v]) => v.qualification || v.resolution)
      .map(([k, v]) => [k, Object.fromEntries(Object.entries(v).filter(([, h]) => h).map(([a, h]) => [a, Number(h)]))]))
    // Compte de lecture : envoyé seulement s'il est saisi (un champ vide le conserve) ou si son effacement est demandé.
    const credentials = wz.dropCredentials
      ? { wazuh_indexer_user: null, wazuh_indexer_password: null }
      : { ...(wz.user ? { wazuh_indexer_user: wz.user } : {}), ...(wz.password ? { wazuh_indexer_password: wz.password } : {}) }
    const ok = await track(() => api(`/admin/clients/${client.key}`, { method: 'PATCH', json: {
      contact_emails: emails.split(/[,\s;]+/).filter(Boolean),
      retention_months: retention === '' ? null : Number(retention),
      max_attachment_mb: maxMb === '' ? null : Number(maxMb),
      severity_grid: grid, sla: Object.keys(cleanSla).length ? cleanSla : null,
      wazuh_dashboard_url: wz.dashboard.trim() || null, wazuh_indexer_url: wz.indexer.trim() || null,
      wazuh_index_pattern: wz.pattern.trim() || null, wazuh_tls_verify: wz.verify, wazuh_ca_pem: wz.ca.trim() || null,
      ...credentials } }))
    if (!ok) return
    setWz((x) => ({ ...x, user: '', password: '', dropCredentials: false }))   // un secret saisi ne reste pas dans le formulaire
    onSaved()
  }
  return (
    <form className="subform" onSubmit={save}>
      <label>{tr("Contacts de notification (séparés par des virgules)")}<input value={emails} onChange={(e) => setEmails(e.target.value)} /></label>
      <label>{tr("Rétention des alertes brutes, en mois (6 minimum, vide = durée par défaut de l'instance)")}<input type="number" min="6" max="120" value={retention} onChange={(e) => setRetention(e.target.value)} /></label>
      <label>{tr("Taille maximale d'une pièce, en Mo (1 à 20, vide = 20 : plafond fixé par le plan)")}<input type="number" min="1" max="20" value={maxMb} onChange={(e) => setMaxMb(e.target.value)} /></label>
      <h3>{tr("Grille de gravité")} {grid ? tr('(propre au client)') : tr('(grille par défaut)')}</h3>
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">{tr("Dommages \\ Importance")}</th>{Object.entries(IMPORTANCES).map(([k, v]) => <th key={k} scope="col">{v}</th>)}</tr></thead>
        <tbody>{Object.entries(DOMMAGES).map(([d, dl]) => (
          <tr key={d}><th scope="row">{dl}</th>{Object.keys(IMPORTANCES).map((i) => (
            <td key={i}><select aria-label={`${dl}, ${IMPORTANCES[i]}`} value={g[d][i]}
              onChange={(e) => setGrid({ ...g, [d]: { ...g[d], [i]: e.target.value } })}>
              {SEVS.map((s) => <option key={s} value={s}>{tr(s)}</option>)}</select></td>))}</tr>))}
        </tbody></table></div>
      {grid && <button type="button" className="link" onClick={() => setGrid(null)}>{tr("Revenir à la grille par défaut")}</button>}
      <h3>{tr("Délais cibles (heures)")}</h3>
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">{tr("Gravité")}</th><th scope="col">{tr("Qualification")}</th><th scope="col">{tr("Résolution")}</th></tr></thead>
        <tbody>{SEVS.map((s) => (
          <tr key={s}><th scope="row">{tr(s)}</th>{['qualification', 'resolution'].map((k) => (
            <td key={k}><input type="number" min="0" step="0.5" aria-label={`${tr(s)}, ${k === 'qualification' ? tr('Qualification') : tr('Résolution')}`} value={sla[s]?.[k] ?? ''}
              onChange={(e) => setSla({ ...sla, [s]: { ...sla[s], [k]: e.target.value } })} /></td>))}</tr>))}
        </tbody></table></div>
      <WazuhSettings client={client} v={wz} set={(patch) => setWz((x) => ({ ...x, ...patch }))} />
      <div className="row gap end wrap"><ActionStatus state={status} /><button className="primary">{tr("Enregistrer")}</button></div>
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
    try { await api('/admin/clients', { method: 'POST', json: { key: fd.get('key'), name: fd.get('name') } }); e.target.reset(); setMsg(tr('Client créé.')); load() } catch (err) { setError(err.message) }
  }
  return (
    <section className="card section" aria-label={tr("Clients")}>
      <header className="section-head"><h2>{tr("Clients")}</h2></header>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      <form className="row gap wrap" onSubmit={create}>
        <label>{tr("Clé (ex. ACME)")}<input name="key" required pattern="[A-Za-z0-9]{1,16}" /></label>
        <label className="grow">{tr("Nom")}<input name="name" required /></label>
        <button className="primary">{tr("Ajouter")}</button>
      </form>
      {items?.map((c) => (
        <div key={c.key} className="client-block">
          <div className="row between wrap">
            <div><span className="mono strong">{c.key}</span> — {c.name} <span className="muted small">({c.tickets} ticket{c.tickets > 1 ? 's' : ''})</span></div>
            <button type="button" className="small-btn" aria-expanded={open === c.key} onClick={() => setOpen(open === c.key ? null : c.key)}>{open === c.key ? tr('Fermer') : tr('Paramétrer')}</button>
          </div>
          {open === c.key && <ClientEditor client={c} onSaved={() => { setMsg(tr('Client enregistré.')); load() }} />}
        </div>
      ))}
    </section>
  )
}
