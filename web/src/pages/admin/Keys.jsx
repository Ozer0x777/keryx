import { t as tr } from '../../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import { useConfirm } from '../../components/Confirm.jsx'
import OneTime from '../../components/OneTime.jsx'
import { formatUtc } from '../../labels.js'

export default function Keys() {
  const [items, setItems] = useState(null)
  const [clients, setClients] = useState([])
  const [secret, setSecret] = useState(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try { const [k, c] = await Promise.all([api('/admin/api-keys'), api('/admin/clients')]); setItems(k.items); setClients(c.items) } catch (e) { setError(e.message) }
  }, [])
  useEffect(() => { load() }, [load])
  const [ask, dialog] = useConfirm()
  const act = async (fn, title) => {
    setError('')
    try { const r = await fn(); if (r?.key) setSecret({ title, items: [[tr("Clé d'API"), r.key]] }); load() } catch (e) { setError(e.message) }
  }
  const rotate = async (k) => {
    const r = await ask({
      title: tr('Remplacer la clé « {name} » de {client} ?', { name: k.name, client: k.client }),
      body: <p>{tr("Une nouvelle clé est créée et celle-ci est révoquée aussitôt : le manager Wazuh sera rejeté tant que la nouvelle clé n'y est pas configurée.")}</p>,
      confirm: tr('Créer la clé de remplacement'), danger: true,
      action: () => api(`/admin/api-keys/${k.id}/rotate`, { method: 'POST' }),
    })
    if (r) act(async () => r.result, tr('Clé de remplacement'))
  }
  const revoke = async (k) => {
    const r = await ask({
      title: tr('Révoquer la clé « {name} » de {client} ?', { name: k.name, client: k.client }),
      body: <p>{tr("Le manager Wazuh qui l'utilise sera rejeté et ses alertes ne seront plus reçues. Une clé révoquée ne se rétablit pas.")}</p>,
      confirm: tr('Révoquer la clé'), danger: true,
      action: () => api(`/admin/api-keys/${k.id}/revoke`, { method: 'POST' }),
    })
    if (r) act(async () => r.result, tr('Révoquée'))
  }
  const create = (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    act(() => api('/admin/api-keys', { method: 'POST', json: { client: fd.get('client'), name: fd.get('name') } }), tr('Nouvelle clé'))
    e.target.reset()
  }
  const silent = (items || []).filter((k) => k.silent)
  return (
    <section className="card section" aria-label={tr("Clés d'API")}>
      <header className="section-head"><h2>{tr("Clés d'API et sources Wazuh")}</h2></header>
      {error && <p className="error" role="alert">{error}</p>}
      {silent.length > 0 && <p className="banner warn" role="status">{tr('{n} source(s) muette(s) depuis plus de 24 h : {list}.', { n: silent.length, list: silent.map((k) => `${k.client}/${k.name}`).join(', ') })}</p>}
      {secret && <OneTime {...secret} onClose={() => setSecret(null)} />}
      <form className="row gap wrap" onSubmit={create}>
        <label>{tr("Client")}<select name="client" required>{clients.map((c) => <option key={c.key} value={c.key}>{c.key}</option>)}</select></label>
        <label className="grow">{tr("Nom du manager Wazuh")}<input name="name" required placeholder={tr("wazuh-manager-01")} /></label>
        <button className="primary">{tr("Créer une clé")}</button>
      </form>
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col">{tr("Client")}</th><th scope="col">{tr("Nom")}</th><th scope="col">{tr("Préfixe")}</th><th scope="col">{tr("Dernière alerte reçue")}</th><th scope="col">{tr("État")}</th><th scope="col">{tr("Actions")}</th></tr></thead>
        <tbody>
          {items === null && <tr><td colSpan="6" className="muted">{tr("Chargement…")}</td></tr>}
          {items?.map((k) => (
            <tr key={k.id}>
              <td className="mono">{k.client}</td><td>{k.name}</td><td className="mono small">{k.prefix}…</td>
              <td className="mono small">{formatUtc(k.last_used_at)}</td>
              <td>{k.revoked ? <span className="pill">{tr("Révoquée")}</span> : k.silent ? <span className="pill warn">{tr("Muette")}</span> : <span className="pill ok">{tr("Active")}</span>}</td>
              <td>{!k.revoked && <div className="row gap">
                <button type="button" className="small-btn" onClick={() => rotate(k)}>{tr("Rotation")}</button>
                <button type="button" className="small-btn danger" onClick={() => revoke(k)}>{tr("Révoquer")}</button>
              </div>}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
      {dialog}
    </section>
  )
}
