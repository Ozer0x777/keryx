import { useState } from 'react'
import { api } from '../api.js'
import OneTime from '../components/OneTime.jsx'

export default function Login({ onDone }) {
  const [step, setStep] = useState(1)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [enroll, setEnroll] = useState(null)
  const [activation, setActivation] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [newPwd2, setNewPwd2] = useState('')
  const [codes, setCodes] = useState(null)

  const submitPassword = async (e) => {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      const r = await api('/auth/login', { method: 'POST', json: { username, password } })
      setPassword('')
      if (r.next === 'enroll') setStep(4)
      else setStep(2)
    } catch (err) {
      setError(err.message)
    } finally { setBusy(false) }
  }

  const submitActivation = async (e) => {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      setEnroll(await api('/auth/enroll/start', { method: 'POST', json: { activation_code: activation } }))
      setActivation('')
      setStep(3)
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  const submitCode = async (e) => {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      await api('/auth/totp', { method: 'POST', json: useRecovery ? { recovery_code: code } : { code } })
      await onDone()
    } catch (err) {
      setError(err.status === 401 && step === 2 && !/verrouill/i.test(err.message) ? 'Code invalide, ou session expirée : recommencez si besoin.' : err.message)
    } finally { setBusy(false) }
  }

  const submitEnroll = async (e) => {
    e.preventDefault()
    setError('')
    if (newPwd !== newPwd2) { setError('Les deux mots de passe ne correspondent pas.'); return }
    setBusy(true)
    try {
      const r = await api('/auth/enroll/finish', { method: 'POST', json: { code, new_password: newPwd } })
      setNewPwd(''); setNewPwd2(''); setCode('')
      setCodes(r.recovery_codes)
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  return (
    <div className="login">
      <section className="login-side" aria-label="Présentation">
        <span className="brand big">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#5B8DEF" strokeWidth="2" aria-hidden="true">
            <path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z" /><path d="M9 12l2 2 4-4" />
          </svg>
          <span>Keryx</span>
        </span>
        <p className="tagline">Gestion des incidents de sécurité</p>
        <ul>
          <li>Double authentification obligatoire pour tous les comptes.</li>
          <li>Chaque connexion et chaque action sont journalisées.</li>
          <li>Accès réservé aux personnes habilitées.</li>
        </ul>
      </section>
      <main className="login-main">
        <div className="card login-card">
          {step === 3 ? (
            codes ? (
              <div>
                <h1>Compte activé</h1>
                <OneTime title="Vos codes de secours" items={[['Codes de secours (usage unique)', codes]]} onClose={onDone} />
              </div>
            ) : (
              <form onSubmit={submitEnroll}>
                <span className="eyebrow">Première connexion</span>
                <h1>Activer votre compte</h1>
                <p className="muted">1. Ajoutez ce compte dans votre application d'authentification (FreeOTP, Aegis, Google Authenticator…) avec la clé ci-dessous.</p>
                <p className="mono small" style={{ wordBreak: 'break-all' }} data-testid="totp-secret">{enroll?.totp_secret}</p>
                <details><summary className="small">Adresse de configuration (otpauth)</summary><p className="mono small" style={{ wordBreak: 'break-all' }}>{enroll?.totp_uri}</p></details>
                <p className="muted">2. Saisissez le code à 6 chiffres affiché, puis choisissez votre mot de passe personnel.</p>
                <label htmlFor="ecode">Code TOTP</label>
                <input id="ecode" className="otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.trim())} required />
                <label htmlFor="np">Nouveau mot de passe (12 caractères minimum)</label>
                <input id="np" type="password" autoComplete="new-password" minLength={12} value={newPwd} onChange={(e) => setNewPwd(e.target.value)} required />
                <label htmlFor="np2">Confirmer le mot de passe</label>
                <input id="np2" type="password" autoComplete="new-password" minLength={12} value={newPwd2} onChange={(e) => setNewPwd2(e.target.value)} required />
                {error && <p className="error" role="alert">{error}</p>}
                <button className="primary wide" disabled={busy}>Activer mon compte</button>
              </form>
            )
          ) : step === 4 ? (
            <form onSubmit={submitActivation}>
              <span className="eyebrow">Première connexion</span>
              <h1>Code d'activation</h1>
              <p className="muted">Saisissez le code d'activation qui vous a été remis (par courriel ou par votre administrateur).</p>
              <label htmlFor="act">Code d'activation</label>
              <input id="act" autoComplete="off" value={activation} onChange={(e) => setActivation(e.target.value)} required />
              {error && <p className="error" role="alert">{error}</p>}
              <button className="primary wide" disabled={busy}>Continuer</button>
            </form>
          ) : step === 1 ? (
            <form onSubmit={submitPassword}>
              <span className="eyebrow">Étape 1 sur 2</span>
              <h1>Connexion</h1>
              <label htmlFor="u">Identifiant</label>
              <input id="u" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
              <label htmlFor="p">Mot de passe</label>
              <input id="p" type="password" autoComplete="current-password" value={password}
                onChange={(e) => setPassword(e.target.value)} required />
              {error && <p className="error" role="alert">{error}</p>}
              <button className="primary wide" disabled={busy}>Continuer</button>
            </form>
          ) : (
            <form onSubmit={submitCode}>
              <span className="eyebrow">Étape 2 sur 2</span>
              <h1>{useRecovery ? 'Code de secours' : 'Code de vérification'}</h1>
              <p className="muted">
                {useRecovery ? "Saisissez l'un de vos codes de secours (usage unique)."
                  : "Saisissez le code à 6 chiffres de votre application d'authentification."}
              </p>
              <label htmlFor="otp">{useRecovery ? 'Code de secours' : 'Code TOTP'}</label>
              <input id="otp" className={useRecovery ? '' : 'otp'} inputMode={useRecovery ? 'text' : 'numeric'}
                autoComplete="one-time-code" maxLength={useRecovery ? 32 : 6} value={code}
                onChange={(e) => setCode(e.target.value.trim())} required />
              {error && <p className="error" role="alert">{error}</p>}
              <button className="primary wide" disabled={busy}>Vérifier</button>
              <div className="row between small">
                <button type="button" className="link" onClick={() => { setUseRecovery(!useRecovery); setCode('') }}>
                  {useRecovery ? 'Utiliser le code TOTP' : 'Utiliser un code de secours'}
                </button>
                <button type="button" className="link" onClick={() => { setStep(1); setCode(''); setError('') }}>Retour</button>
              </div>
              <p className="muted small">Après plusieurs échecs, le compte est verrouillé 15 minutes.</p>
            </form>
          )}
        </div>
      </main>
    </div>
  )
}
