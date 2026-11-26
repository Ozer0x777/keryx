import { t as tr } from '../../i18n.js'
import { useLocalList } from '../../components/LocalList.jsx'

const texteCompte = (u) => [u.username, u.display_name, u.email, u.role, ...u.clients].filter(Boolean).join(' ')
import { useCallback, useEffect, useId, useState } from 'react'
import { api } from '../../api.js'
import { useAuth } from '../../App.jsx'
import { Modal, useConfirm } from '../../components/Confirm.jsx'
import OneTime from '../../components/OneTime.jsx'
import { utcClock } from '../../dates.js'
import { formatUtc, ROLES } from '../../labels.js'

// Édition d'un compte : nom affiché, rôle et clients rattachés (PATCH /admin/users/{identifiant}, tracé dans l'audit).
// Le courriel est affiché mais jamais modifiable : c'est la clé de liaison de l'identité SSO ; il n'est pas envoyé.
// Les règles de rôle du serveur sont reprises ici pour être signalées sous le champ avant l'envoi : un Admin n'a aucun
// client (séparation administrateur / opérateur), un Client exactement un, un analyste ou un manager au moins un.
function EditUser({ user, clients, self, onSaved, onClose }) {
  const uid = useId()
  const [name, setName] = useState(user.display_name)
  const [role, setRole] = useState(user.role)
  const [picked, setPicked] = useState(user.clients)
  const [errors, setErrors] = useState({})
  const [failure, setFailure] = useState('')
  const [busy, setBusy] = useState(false)
  const single = role === 'client'

  const pickRole = (next) => {
    setRole(next); setErrors({})
    if (next === 'admin') setPicked([])
    else if (next === 'client') setPicked((p) => p.slice(0, 1))
  }
  const togglePick = (key) => setPicked((p) => (single ? [key] : p.includes(key) ? p.filter((k) => k !== key) : [...p, key]))

  const submit = async (e) => {
    e.preventDefault()
    if (busy) return
    const found = {}
    if (!name.trim()) found.name = tr('Ce champ est obligatoire.')
    if (role === 'client' && picked.length !== 1) found.clients = tr('Un compte Client est rattaché à exactement un client.')
    if ((role === 'analyst' || role === 'manager') && picked.length === 0) found.clients = tr('Rattacher au moins un client à ce compte.')
    setErrors(found); setFailure('')
    if (found.name) { e.currentTarget.querySelector('[name=display_name]').focus(); return }
    if (found.clients) { e.currentTarget.querySelector('[name=clients]')?.focus(); return }
    // Seuls les champs modifiés sont envoyés ; le courriel ne l'est jamais.
    const json = {}
    if (name.trim() !== user.display_name) json.display_name = name.trim()
    if (role !== user.role) json.role = role
    const sameClients = picked.length === user.clients.length && picked.every((k) => user.clients.includes(k))
    if (!sameClients || role !== user.role) json.clients = role === 'admin' ? [] : clients.map((c) => c.key).filter((k) => picked.includes(k))
    if (Object.keys(json).length === 0) { onClose(); return }
    setBusy(true)
    try {
      await api(`/admin/users/${encodeURIComponent(user.username)}`, { method: 'PATCH', json })
      onSaved(user)
    } catch (err) { setBusy(false); setFailure(err.message) }
  }

  return (
    <Modal labelledBy={`${uid}-t`} locked={busy} onDismiss={onClose}>
      <form onSubmit={submit} noValidate>
        <h2 id={`${uid}-t`}>{tr('Modifier le compte {u}', { u: user.username })}</h2>
        <div className="field">
          <label htmlFor={`${uid}-n`}>{tr("Nom affiché")}</label>
          <input id={`${uid}-n`} name="display_name" value={name} maxLength={200} autoComplete="off" onChange={(e) => setName(e.target.value)}
            aria-required="true" aria-invalid={errors.name ? 'true' : undefined} aria-describedby={errors.name ? `${uid}-ne` : undefined} />
          {errors.name && <p className="field-error" id={`${uid}-ne`}>{errors.name}</p>}
        </div>
        <div className="field">
          <label htmlFor={`${uid}-e`}>{tr("Courriel")}</label>
          <input id={`${uid}-e`} type="email" value={user.email || ''} placeholder={tr('Aucun courriel')} readOnly aria-describedby={`${uid}-eh`} />
          <p className="field-hint" id={`${uid}-eh`}>{tr("Non modifiable : le courriel sert de clé de liaison à l'identité SSO du compte.")}</p>
        </div>
        <div className="field">
          <label htmlFor={`${uid}-r`}>{tr("Rôle")}</label>
          <select id={`${uid}-r`} value={role} disabled={self} onChange={(e) => pickRole(e.target.value)} aria-describedby={`${uid}-rh`}>
            {Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <p className="field-hint" id={`${uid}-rh`}>{self
            ? tr('Vous ne pouvez pas modifier votre propre rôle.')
            : role === 'admin'
              ? tr("Un Admin gère les comptes et la plateforme ; il n'a pas accès au contenu des tickets et n'est rattaché à aucun client.")
              : tr('Un changement de rôle ou de clients ferme les sessions ouvertes de ce compte.')}</p>
        </div>
        {role !== 'admin' && (
          <fieldset className="fieldset" aria-describedby={errors.clients ? `${uid}-ce` : undefined}>
            <legend>{single ? tr('Client rattaché (un seul pour un compte Client)') : tr('Clients rattachés')}</legend>
            {clients.length === 0 && <p className="muted small">{tr("Aucun client n'existe encore.")}</p>}
            {clients.map((c) => (
              <label key={c.key} className="check">
                <input type={single ? 'radio' : 'checkbox'} name="clients" value={c.key} checked={picked.includes(c.key)} onChange={() => togglePick(c.key)} /> {c.key} — {c.name}
              </label>
            ))}
            {errors.clients && <p className="field-error" id={`${uid}-ce`}>{errors.clients}</p>}
          </fieldset>
        )}
        {failure && <p className="error" role="alert">{failure}</p>}
        <div className="dialog-actions">
          <button type="button" data-cancel onClick={onClose} disabled={busy}>{tr('Annuler')}</button>
          <button type="submit" className="primary" disabled={busy} aria-busy={busy || undefined}>{tr('Enregistrer')}</button>
        </div>
      </form>
    </Modal>
  )
}

export default function Users() {
  const { me } = useAuth()
  const [items, setItems] = useState(null)
  const list = useLocalList(items, texteCompte, tr('Pages des comptes'))
  const [clients, setClients] = useState([])
  const [form, setForm] = useState(null)
  const [editing, setEditing] = useState(null)
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
      {editing && <EditUser user={editing} clients={clients} self={editing.username === me.username} onClose={() => setEditing(null)}
        onSaved={(u) => { setEditing(null); done(tr('Compte {u} enregistré à {h}.', { u: u.username, h: utcClock() })) }} />}
      {form && (
        <form className="subform" onSubmit={create}>
          <div className="grid2">
            <label>{tr("Identifiant")}<input name="username" required pattern="[A-Za-z0-9._-]{3,64}" autoComplete="off" /></label>
            <label>{tr("Nom affiché")}<input name="display_name" required /></label>
            <label>{tr("Courriel (facultatif, non modifiable ensuite)")}<input name="email" type="email" /></label>
            <label>{tr("Rôle")}<select name="role" defaultValue="analyst">{Object.entries(ROLES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          </div>
          <fieldset className="fieldset"><legend>{tr("Clients (aucun pour un Admin, un seul pour un Client)")}</legend>
            {clients.map((c) => <label key={c.key} className="check"><input type="checkbox" name="clients" value={c.key} /> {c.key} — {c.name}</label>)}
          </fieldset>
          <label>{tr("Mot de passe initial (12 caractères minimum)")}<input name="password" type="password" minLength={12} required autoComplete="new-password" /></label>
          <div className="row gap end"><button type="button" onClick={() => setForm(null)}>{tr("Annuler")}</button><button className="primary">{tr("Créer")}</button></div>
        </form>
      )}
      {list.search}
      <div className="table-wrap">
        <table className="grid">
          <thead><tr><th scope="col">{tr("Identifiant")}</th><th scope="col">{tr("Nom")}</th><th scope="col">{tr("Rôle")}</th><th scope="col">{tr("Clients")}</th><th scope="col">{tr("Dernière connexion")}</th><th scope="col">{tr("État")}</th><th scope="col">{tr("Actions")}</th></tr></thead>
          <tbody>
            {items === null && <tr><td colSpan="7" className="muted">{tr("Chargement…")}</td></tr>}
            {list.rows?.map((u) => (
              <tr key={u.username}>
                <td className="mono">{u.username}</td><td>{u.display_name}{u.email && <div className="muted small">{u.email}</div>}</td><td>{ROLES[u.role]}</td>
                <td className="mono small">{u.clients.join(', ') || '—'}</td>
                <td className="mono small">{formatUtc(u.last_login_at)}</td>
                <td>{!u.active ? <span className="pill">{tr("Désactivé")}</span> : !u.enrolled ? <span className="pill warn">{tr("À activer")}</span> : u.locked ? <span className="pill danger">{tr("Verrouillé")}</span> : <span className="pill ok">{tr("Actif")}</span>}{u.sso && <span className="pill" title={tr("Identité fédérée liée (SSO)")} style={{ marginLeft: 6 }}>{tr("SSO")}</span>}</td>
                <td><div className="row gap wrap">
                  <button type="button" className="small-btn" aria-label={tr('Modifier le compte {u}', { u: u.username })} onClick={() => setEditing(u)}>{tr("Modifier")}</button>
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
      {list.pager}
    </section>
  )
}
