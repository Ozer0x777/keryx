import { t as tr } from '../../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import { useConfirm } from '../../components/Confirm.jsx'
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

  const [ask, dialog] = useConfirm()

  const run = async (fn, ok) => {
    setError(''); setMsg('')
    try { const r = await fn(); setMsg(ok); await load(); return r } catch (e) { setError(e.message); return null }
  }
  // Suite d'une action confirmée dans un dialogue (son échec s'y est affiché) : message de statut et liste à jour.
  const done = async (text) => { setError(''); setMsg(text); await load() }

  // Code d'activation : envoyé par courriel au titulaire quand c'est possible (l'Admin ne le voit pas) ; sinon affiché
  // une seule fois, dans l'encart des secrets à usage unique, pour être transmis hors bande.
  const grant = (r, base) => {
    if (r.activation === 'courriel') { setSecret(null); return `${base} ${tr("Le code d'activation a été envoyé par courriel au titulaire.")}` }
    setSecret({ title: tr("Code d'activation de {u}", { u: r.username }), items: [[tr("Code d'activation (valable 72 h, à transmettre hors bande)"), r.enrollment_code]] })
    return `${base} ${tr("Le code d'activation est affiché ci-dessous, une seule fois.")}`
  }

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
      setMsg(grant(r, tr('Compte {u} créé. Transmettez-lui son mot de passe temporaire par un canal sûr : il activera lui-même sa double authentification à sa première connexion.', { u: r.username })))
    }
  }

  const path = (u) => `/admin/users/${encodeURIComponent(u.username)}`
  const reset2fa = async (u) => {
    const r = await ask({
      title: tr('Réinitialiser la double authentification de {u} ?', { u: u.username }),
      body: <p>{tr("Ses sessions sont fermées, son application TOTP et ses clés de sécurité sont retirées : il devra réenrôler son application à sa prochaine connexion, avec un nouveau code d'activation.")}</p>,
      confirm: tr('Réinitialiser la 2FA'), danger: true,
      action: () => api(`${path(u)}/reset-2fa`, { method: 'POST' }),
    })
    if (r) await done(grant(r.result, tr("2FA de {u} réinitialisée : l'utilisateur la réenrôlera à sa prochaine connexion (définissez-lui un mot de passe temporaire si besoin).", { u: u.username })))
  }
  const resetPwd = async (u) => {
    const r = await ask({
      title: tr('Définir un nouveau mot de passe pour {u}', { u: u.username }),
      body: <p>{tr("Ses sessions ouvertes sont fermées. Transmettez-lui ce mot de passe temporaire par un canal sûr.")}</p>,
      fields: [
        { name: 'password', type: 'password', label: tr('Nouveau mot de passe (12 caractères minimum)'), minLength: 12, maxLength: 256, autoComplete: 'new-password' },
        { name: 'confirm', type: 'password', label: tr('Confirmer le nouveau mot de passe'), maxLength: 256, autoComplete: 'new-password',
          validate: (v, all) => (v === all.password ? '' : tr('Les deux mots de passe ne correspondent pas.')) },
      ],
      confirm: tr('Changer le mot de passe'),
      action: ({ password }) => api(`${path(u)}/reset-password`, { method: 'POST', json: { password } }),
    })
    if (r) await done(r.result.activation ? grant(r.result, tr('Mot de passe réinitialisé.')) : tr('Mot de passe réinitialisé.'))
  }
  const toggle = async (u) => {
    if (!u.active) { run(() => api(path(u), { method: 'PATCH', json: { active: true } }), tr('Compte réactivé.')); return }
    const r = await ask({
      title: tr('Désactiver le compte {u} ?', { u: u.username }),
      body: <p>{tr("Ses sessions sont fermées et il ne peut plus se connecter. Le compte, ses affectations et son historique sont conservés ; il peut être réactivé.")}</p>,
      confirm: tr('Désactiver le compte'), danger: true,
      action: () => api(path(u), { method: 'PATCH', json: { active: false } }),
    })
    if (r) await done(tr('Compte désactivé.'))
  }
  const unlinkSso = async (u) => {
    const r = await ask({
      title: tr("Délier l'identité SSO de {u} ?", { u: u.username }),
      body: <p>{tr("L'identité fédérée sera liée de nouveau à sa prochaine connexion SSO, si son identifiant et son courriel vérifié correspondent.")}</p>,
      confirm: tr("Délier l'identité SSO"),
      action: () => api(`${path(u)}/unlink-sso`, { method: 'POST' }),
    })
    if (r) await done(tr('Identité SSO déliée.'))
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
      {dialog}
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
                  {u.sso && <button type="button" className="small-btn" onClick={() => unlinkSso(u)}>{tr("Délier SSO")}</button>}
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
