import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import OneTime from '../components/OneTime.jsx'
import { formatUtc, ROLES } from '../labels.js'

export default function Profile() {
  const { me } = useAuth()
  const [sessions, setSessions] = useState(null)
  const [secret, setSecret] = useState(null)
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')
  const load = useCallback(() => api('/me/sessions').then((r) => setSessions(r.items)).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])

  const changePassword = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    setError(''); setMsg('')
    if (fd.get('new') !== fd.get('confirm')) { setError('Les deux mots de passe ne correspondent pas.'); return }
    try {
      await api('/me/password', { method: 'POST', json: { current: fd.get('current'), new: fd.get('new') } })
      e.target.reset(); setMsg('Mot de passe modifié. Vos autres sessions ont été fermées.'); load()
    } catch (err) { setError(err.message) }
  }
  const regen = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    setError(''); setMsg('')
    try {
      const r = await api('/me/recovery-codes', { method: 'POST', json: { password: fd.get('password') } })
      e.target.reset(); setSecret({ title: 'Nouveaux codes de secours (les anciens sont invalides)', items: [['Codes de secours', r.recovery_codes]] })
    } catch (err) { setError(err.message) }
  }
  const revoke = async (id) => {
    try { await api(`/me/sessions/${id}`, { method: 'DELETE' }); load() } catch (err) { setError(err.message) }
  }

  return (
    <>
      <header className="page-head"><div><h1>Mon profil</h1><p className="muted">{me.display_name} · {ROLES[me.role]}</p></div></header>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {secret && <OneTime {...secret} onClose={() => setSecret(null)} />}
      <section className="card section" aria-label="Mot de passe">
        <header className="section-head"><h2>Changer de mot de passe</h2></header>
        <form onSubmit={changePassword} className="narrow">
          <label>Mot de passe actuel<input name="current" type="password" required autoComplete="current-password" /></label>
          <label>Nouveau mot de passe (12 caractères minimum)<input name="new" type="password" minLength={12} required autoComplete="new-password" /></label>
          <label>Confirmer le nouveau mot de passe<input name="confirm" type="password" minLength={12} required autoComplete="new-password" /></label>
          <button className="primary">Modifier</button>
        </form>
      </section>
      <section className="card section" aria-label="Codes de secours">
        <header className="section-head"><h2>Codes de secours</h2></header>
        <p className="muted small">Génère 10 nouveaux codes à usage unique ; les précédents cessent de fonctionner.</p>
        <form onSubmit={regen} className="row gap wrap">
          <label>Mot de passe<input name="password" type="password" required autoComplete="current-password" /></label>
          <button style={{ marginBottom: 10 }}>Régénérer</button>
        </form>
      </section>
      <section className="card section" aria-label="Sessions">
        <header className="section-head"><h2>Sessions actives</h2></header>
        <div className="table-wrap"><table className="grid">
          <thead><tr><th scope="col">Ouverte le</th><th scope="col">Dernière activité</th><th scope="col"><span className="sr-only">Action</span></th></tr></thead>
          <tbody>{sessions?.map((s) => (
            <tr key={s.id}><td className="mono small">{formatUtc(s.created_at)}</td><td className="mono small">{formatUtc(s.last_seen_at)}</td>
              <td><button type="button" className="small-btn danger" onClick={() => revoke(s.id)}>Fermer</button></td></tr>))}
          </tbody></table></div>
      </section>
    </>
  )
}
