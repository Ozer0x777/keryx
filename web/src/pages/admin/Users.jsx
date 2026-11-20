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

  const create = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    const role = fd.get('role')
    const picked = fd.getAll('clients')
    const r = await run(() => api('/admin/users', { method: 'POST', json: {
      username: fd.get('username'), display_name: fd.get('display_name'), email: fd.get('email') || null,
      role, clients: role === 'admin' ? [] : picked, password: fd.get('password') } }), 'Compte créé.')
    if (r) {
      setForm(null)
      setSecret({ title: `Compte ${r.username}`, items: [['Code TOTP (URI)', r.totp_uri], ['Secret TOTP', r.totp_secret], ['Codes de secours', r.recovery_codes]] })
    }
  }

  const reset2fa = async (u) => {
    if (!window.confirm(`Réinitialiser la 2FA de ${u.username} ? Ses sessions seront fermées.`)) return
    const r = await run(() => api(`/admin/users/${encodeURIComponent(u.username)}/reset-2fa`, { method: 'POST' }), '2FA réinitialisée.')
    if (r) setSecret({ title: `2FA de ${r.username}`, items: [['Code TOTP (URI)', r.totp_uri], ['Secret TOTP', r.totp_secret], ['Codes de secours', r.recovery_codes]] })
  }
  const resetPwd = async (u) => {
    const password = window.prompt(`Nouveau mot de passe pour ${u.username} (12 caractères minimum)`)
    if (!password) return
    run(() => api(`/admin/users/${encodeURIComponent(u.username)}/reset-password`, { method: 'POST', json: { password } }), 'Mot de passe réinitialisé.')
  }
  const toggle = (u) => {
    if (u.active && !window.confirm(`Désactiver ${u.username} ?`)) return
    run(() => api(`/admin/users/${encodeURIComponent(u.username)}`, { method: 'PATCH', json: { active: !u.active } }), u.active ? 'Compte désactivé.' : 'Compte réactivé.')
  }

  return (
    <section className="card section" aria-label="Comptes">
      <header className="section-head">
        <h2>Comptes</h2>
        <button type="button" className="primary" onClick={() => setForm(form ? null : {})}>Nouveau compte</button>
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {secret && <OneTime {...secret} onClose={() => setSecret(null)} />}
      {form && (
        <form className="subform" onSubmit={create}>
          <div className="grid2">
            <label>Identifiant<input name="username" required pattern="[A-Za-z0-9._-]{3,64}" autoComplete="off" /></label>
            <label>Nom affiché<input name="display_name" required /></label>
            <label>Courriel (facultatif)<input name="email" type="email" /></label>
            <label>Rôle<select name="role" defaultValue="analyst">{Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          </div>
          <fieldset className="fieldset"><legend>Clients (aucun pour un Admin, un seul pour un Client)</legend>
            {clients.map((c) => <label key={c.key} className="check"><input type="checkbox" name="clients" value={c.key} /> {c.key} — {c.name}</label>)}
          </fieldset>
          <label>Mot de passe initial (12 caractères minimum)<input name="password" type="password" minLength={12} required autoComplete="new-password" /></label>
          <div className="row gap end"><button type="button" onClick={() => setForm(null)}>Annuler</button><button className="primary">Créer</button></div>
        </form>
      )}
      <div className="table-wrap">
        <table className="grid">
          <thead><tr><th scope="col">Identifiant</th><th scope="col">Nom</th><th scope="col">Rôle</th><th scope="col">Clients</th><th scope="col">Dernière connexion</th><th scope="col">État</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {items === null && <tr><td colSpan="7" className="muted">Chargement…</td></tr>}
            {items?.map((u) => (
              <tr key={u.username}>
                <td className="mono">{u.username}</td><td>{u.display_name}</td><td>{ROLES[u.role]}</td>
                <td className="mono small">{u.clients.join(', ') || '—'}</td>
                <td className="mono small">{formatUtc(u.last_login_at)}</td>
                <td>{!u.active ? <span className="pill">Désactivé</span> : u.locked ? <span className="pill danger">Verrouillé</span> : <span className="pill ok">Actif</span>}</td>
                <td><div className="row gap wrap">
                  <button type="button" className="small-btn" onClick={() => reset2fa(u)}>Réinit. 2FA</button>
                  <button type="button" className="small-btn" onClick={() => resetPwd(u)}>Mot de passe</button>
                  <button type="button" className="small-btn danger" onClick={() => toggle(u)}>{u.active ? 'Désactiver' : 'Réactiver'}</button>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
