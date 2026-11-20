import { useState } from 'react'
import { api } from '../api.js'

export default function Login({ onDone }) {
  const [step, setStep] = useState(1)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submitPassword = async (e) => {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      await api('/auth/login', { method: 'POST', json: { username, password } })
      setPassword('')
      setStep(2)
    } catch (err) {
      setError(err.message)
    } finally { setBusy(false) }
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
          {step === 1 ? (
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
