import { t as tr } from '../../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import OneTime from '../../components/OneTime.jsx'
import { formatUtc, ROLES } from '../../labels.js'

export default function Users() {
  const [items, setItems] = useState(null)
  const [clients, setClients] = useState([])
  const [form, setForm] = useState(null)
  const [secret, setSecret] = useState(null)
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [u, c] = await Promise.all([api('/admin/users'), api('/admin/clients')])
      setItems(u.items); setClients(c.items)
    } catch (e) { setError(e.message) }
  }, [])
  useEffect(() => { load() }, [load])

  const run = async (fn, ok) => {
    setError(''); setMsg('')
    try { const r = await fn(); setMsg(ok); await load(); return r } catch (e) { setError(e.message); return null }
  }

  const grantMsg = (r, base) => r.activation === 'courriel'
    ? `${base} ${tr("Le code d'activation a été envoyé par courriel au titulaire.")}`
    : `${base} ${tr("Code d'activation (affiché une seule fois, à transmettre hors bande) : {code}", { code: r.enrollment_code })}`

  const create = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    const role = fd.get('role')
    const picked = fd.getAll('clients')
    const r = await run(() => api('/admin/users', { method: 'POST', json: {
      username: fd.get('username'), display_name: fd.get('display_name'), email: fd.get('email') || null,
      role, clients: role === 'admin' ? [] : picked, password: fd.get('password') } }), tr('Compte créé.'))
    if (r) {
      setForm(null)
      setMsg(grantMsg(r, tr('Compte {u} créé. Transmettez-lui son mot de passe temporaire par un canal sûr : il activera lui-même sa double authentification à sa première connexion.', { u: r.username })))
    }
  }

  const reset2fa = async (u) => {
    if (!window.confirm(tr('Réinitialiser la 2FA de {u} ? Ses sessions seront fermées et il devra réenrôler son application.', { u: u.username }))) return
    const r = await run(() => api(`/admin/users/${encodeURIComponent(u.username)}/reset-2fa`, { method: 'POST' }), '')
    if (r) setMsg(grantMsg(r, tr("2FA de {u} réinitialisée : l'utilisateur la réenrôlera à sa prochaine connexion (définissez-lui un mot de passe temporaire si besoin).", { u: u.username })))
  }
  const resetPwd = async (u) => {
    const password = window.prompt(tr('Nouveau mot de passe pour {u} (12 caractères minimum)', { u: u.username }))
    if (!password) return
    const r = await run(() => api(`/admin/users/${encodeURIComponent(u.username)}/reset-password`, { method: 'POST', json: { password } }), tr('Mot de passe réinitialisé.'))
    if (r && r.activation) setMsg(grantMsg(r, tr('Mot de passe réinitialisé.')))
  }
  const toggle = (u) => {
    if (u.active && !window.confirm(tr('Désactiver {u} ?', { u: u.username }))) return
    run(() => api(`/admin/users/${encodeURIComponent(u.username)}`, { method: 'PATCH', json: { active: !u.active } }), u.active ? tr('Compte désactivé.') : tr('Compte réactivé.'))
  }

  return (
    <section className="card section" aria-label={tr("Comptes")}>
      <header className="section-head">
        <h2>{tr("Comptes")}</h2>
        <button type="button" className="primary" onClick={() => setForm(form ? null : {})}>{tr("Nouveau compte")}</button>
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {secret && <OneTime {...secret} onClose={() => setSecret(null)} />}
      {form && (
        <form className="subform" onSubmit={create}>
          <div className="grid2">
            <label>{tr("Identifiant")}<input name="username" required pattern="[A-Za-z0-9._-]{3,64}" autoComplete="off" /></label>
            <label>{tr("Nom affiché")}<input name="display_name" required /></label>
            <label>{tr("Courriel (facultatif)")}<input name="email" type="email" /></label>
            <label>{tr("Rôle")}<select name="role" defaultValue="analyst">{Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          </div>
          <fieldset className="fieldset"><legend>{tr("Clients (aucun pour un Admin, un seul pour un Client)")}</legend>
            {clients.map((c) => <label key={c.key} className="check"><input type="checkbox" name="clients" value={c.key} /> {c.key} — {c.name}</label>)}
          </fieldset>
          <label>{tr("Mot de passe initial (12 caractères minimum)")}<input name="password" type="password" minLength={12} required autoComplete="new-password" /></label>
          <div className="row gap end"><button type="button" onClick={() => setForm(null)}>{tr("Annuler")}</button><button className="primary">{tr("Créer")}</button></div>
        </form>
      )}
      <div className="table-wrap">
        <table className="grid">
          <thead><tr><th scope="col">{tr("Identifiant")}</th><th scope="col">{tr("Nom")}</th><th scope="col">{tr("Rôle")}</th><th scope="col">{tr("Clients")}</th><th scope="col">{tr("Dernière connexion")}</th><th scope="col">{tr("État")}</th><th scope="col">{tr("Actions")}</th></tr></thead>
          <tbody>
            {items === null && <tr><td colSpan="7" className="muted">{tr("Chargement…")}</td></tr>}
            {items?.map((u) => (
              <tr key={u.username}>
                <td className="mono">{u.username}</td><td>{u.display_name}</td><td>{ROLES[u.role]}</td>
                <td className="mono small">{u.clients.join(', ') || '—'}</td>
                <td className="mono small">{formatUtc(u.last_login_at)}</td>
                <td>{!u.active ? <span className="pill">{tr("Désactivé")}</span> : !u.enrolled ? <span className="pill warn">{tr("À activer")}</span> : u.locked ? <span className="pill danger">{tr("Verrouillé")}</span> : <span className="pill ok">{tr("Actif")}</span>}{u.sso && <span className="pill" title={tr("Identité fédérée liée (SSO)")} style={{ marginLeft: 6 }}>{tr("SSO")}</span>}</td>
                <td><div className="row gap wrap">
                  <button type="button" className="small-btn" onClick={() => reset2fa(u)}>{tr("Réinit. 2FA")}</button>
                  <button type="button" className="small-btn" onClick={() => resetPwd(u)}>{tr("Mot de passe")}</button>
                  {u.sso && <button type="button" className="small-btn" onClick={() => window.confirm(tr("Délier l'identité SSO de {u} ? Elle sera liée de nouveau à sa prochaine connexion SSO.", { u: u.username })) && run(() => api(`/admin/users/${encodeURIComponent(u.username)}/unlink-sso`, { method: 'POST' }), tr('Identité SSO déliée.'))}>{tr("Délier SSO")}</button>}
                  <button type="button" className="small-btn danger" onClick={() => toggle(u)}>{u.active ? tr('Désactiver') : tr('Réactiver')}</button>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
