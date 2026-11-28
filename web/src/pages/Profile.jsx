import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import OneTime from '../components/OneTime.jsx'
import { VirusTotalKey } from '../components/VirusTotal.jsx'
import { getLang, LANGS, setLang, t, t as tr } from '../i18n.js'
import { getTheme, setTheme } from '../theme.js'
import { createCredential, webauthnSupported } from '../webauthn.js'
import { formatUtc, ROLES } from '../labels.js'

export default function Profile() {
  const { me } = useAuth()
  const [sessions, setSessions] = useState(null)
  const [theme, setThemeState] = useState(getTheme)
  const [secret, setSecret] = useState(null)
  const [prefs, setPrefs] = useState(null)
  const [keys, setKeys] = useState([])
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')
  const loadKeys = useCallback(() => api('/me/webauthn').then((r) => setKeys(r.items)).catch(() => {}), [])
  useEffect(() => { loadKeys() }, [loadKeys])
  const addKey = async (e) => {
    e.preventDefault()
    const form = e.target
    const fd = new FormData(form)
    setError(''); setMsg('')
    try {
      const options = await api('/me/webauthn/register/begin', { method: 'POST', json: { password: fd.get('password') } })
      const credential = await createCredential(options)
      await api('/me/webauthn/register/finish', { method: 'POST', json: { credential, name: fd.get('name') } })
      form.reset(); setMsg(t('Clé de sécurité enregistrée.')); loadKeys()
    } catch (err) { setError(err.name === 'NotAllowedError' ? t('Clé de sécurité annulée ou non reconnue.') : err.message) }
  }
  const [ask, dialog] = useConfirm()
  const dropKey = async (k) => {
    const r = await ask({
      title: t('Retirer la clé de sécurité « {name} » ?', { name: k.name }),
      body: <p>{t("Elle ne permettra plus de vous connecter. Le code TOTP et vos codes de secours restent utilisables.")}</p>,
      confirm: t('Retirer la clé'), danger: true,
      action: () => api(`/me/webauthn/${k.id}`, { method: 'DELETE' }),
    })
    if (r) { setError(''); setMsg(t('Clé de sécurité retirée.')); loadKeys() }
  }
  const load = useCallback(() => api('/me/sessions').then((r) => setSessions(r.items)).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])
  useEffect(() => { if (me.role !== 'admin') api('/me/preferences').then(setPrefs).catch(() => {}) }, [me.role])
  const setPref = async (k, v) => {
    const next = { ...prefs.prefs, [k]: v }
    try { await api('/me/preferences', { method: 'PUT', json: { prefs: next } }); setPrefs({ ...prefs, prefs: next }) } catch (e) { setError(e.message) }
  }

  const changePassword = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    setError(''); setMsg('')
    if (fd.get('new') !== fd.get('confirm')) { setError(tr('Les deux mots de passe ne correspondent pas.')); return }
    try {
      await api('/me/password', { method: 'POST', json: { current: fd.get('current'), new: fd.get('new') } })
      e.target.reset(); setMsg(tr('Mot de passe modifié. Vos autres sessions ont été fermées.')); load()
    } catch (err) { setError(err.message) }
  }
  const regen = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    setError(''); setMsg('')
    try {
      const r = await api('/me/recovery-codes', { method: 'POST', json: { password: fd.get('password') } })
      e.target.reset(); setSecret({ title: tr('Nouveaux codes de secours (les anciens sont invalides)'), items: [[tr('Codes de secours'), r.recovery_codes]] })
    } catch (err) { setError(err.message) }
  }
  const revokeOthers = async () => {
    try { const r = await api('/me/sessions', { method: 'DELETE' }); setMsg(tr('{n} autre(s) session(s) fermée(s).', { n: r.fermees })); load() } catch (err) { setError(err.message) }
  }
  const revoke = async (id) => {
    try { await api(`/me/sessions/${id}`, { method: 'DELETE' }); load() } catch (err) { setError(err.message) }
  }

  return (
    <>
      <header className="page-head"><div><h1>{t('Mon profil')}</h1><p className="muted">{me.display_name} · {ROLES[me.role]}</p></div></header>
      {error && <p className="error" role="alert">{error}</p>}
      <p className="live" role="status">{msg}</p>
      {secret && <OneTime {...secret} onClose={() => setSecret(null)} />}
      {dialog}
      <section className="card section" aria-label={t('Langue')}>
        <header className="section-head"><h2>{t('Langue')}</h2></header>
        <select className="narrow-select" aria-label={t('Langue')} value={getLang()} onChange={(e) => setLang(e.target.value)}>{Object.entries(LANGS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
      </section>
      <section className="card section" aria-label={tr('Apparence')}>
        <header className="section-head"><h2>{tr('Apparence')}</h2></header>
        <div className="row wrap gap" role="radiogroup" aria-label={tr('Thème')}>
          {[['clair', tr('Clair (par défaut)')], ['sombre', tr('Sombre')], ['systeme', tr('Selon le système')]].map(([k, l]) => (
            <label key={k} className="check"><input type="radio" name="theme" value={k} checked={theme === k} onChange={() => { setTheme(k); setThemeState(k) }} /> {l}</label>
          ))}
        </div>
        <p className="muted small">{tr('Choix propre à ce navigateur. Les impressions et les PDF restent en clair.')}</p>
      </section>
      <section className="card section" aria-label={tr("Mot de passe")}>
        <header className="section-head"><h2>{tr("Changer de mot de passe")}</h2></header>
        <form onSubmit={changePassword} className="narrow">
          <label>{tr("Mot de passe actuel")}<input name="current" type="password" required autoComplete="current-password" /></label>
          <label>{tr("Nouveau mot de passe (12 caractères minimum)")}<input name="new" type="password" minLength={12} required autoComplete="new-password" /></label>
          <label>{tr("Confirmer le nouveau mot de passe")}<input name="confirm" type="password" minLength={12} required autoComplete="new-password" /></label>
          <button className="primary">{tr("Modifier")}</button>
        </form>
      </section>
      <section className="card section" aria-label={t('Clés de sécurité')}>
        <header className="section-head"><h2>{t('Clés de sécurité (WebAuthn)')}</h2></header>
        <p className="muted small">{t("Une clé de sécurité peut remplacer le code TOTP à la connexion. Le TOTP et vos codes de secours restent utilisables si vous perdez la clé.")}</p>
        {keys.length > 0 && <ul className="found">{keys.map((k) => <li key={k.id}>{k.name} <span className="muted small">· {t('ajoutée le')} {formatUtc(k.created_at)}{k.last_used_at ? ` · ${t('utilisée le')} ${formatUtc(k.last_used_at)}` : ''}</span> <button type="button" className="small-btn danger" onClick={() => dropKey(k)}>{t('Retirer')}</button></li>)}</ul>}
        {webauthnSupported() ? (
          <form onSubmit={addKey} className="row gap wrap">
            <label>{t('Nom de la clé')}<input name="name" required maxLength={80} placeholder={tr("ex. YubiKey bureau")} /></label>
            <label>{t('Mot de passe')}<input name="password" type="password" required autoComplete="current-password" /></label>
            <button>{t('Ajouter une clé')}</button>
          </form>
        ) : <p className="muted small">{t("Ce navigateur ne prend pas en charge les clés de sécurité.")}</p>}
      </section>
      <section className="card section" aria-label={tr("Codes de secours")}>
        <header className="section-head"><h2>{tr("Codes de secours")}</h2></header>
        <p className="muted small">{tr('Génère 10 nouveaux codes à usage unique ; les précédents cessent de fonctionner.')}</p>
        <form onSubmit={regen} className="row gap wrap">
          <label>{tr("Mot de passe")}<input name="password" type="password" required autoComplete="current-password" /></label>
          <button>{tr("Régénérer")}</button>
        </form>
      </section>
      {/* Clé VirusTotal personnelle (ADR-0022) : analyste et manager seulement, et seulement si l'instance l'autorise. */}
      {me.features?.virustotal && <VirusTotalKey />}
      {prefs && (
        <section className="card section" aria-label={tr("Notifications")}>
          <header className="section-head"><h2>{tr("Notifications dans l'interface")}</h2></header>
          {prefs.kinds.map((k) => (
            <label key={k} className="check"><input type="checkbox" checked={prefs.prefs[k]} onChange={(e) => setPref(k, e.target.checked)} /> {{ assignation: tr("Ticket qui m'est affecté"), mention: tr('Mention dans un commentaire'), echeance: tr('Échéance dépassée'), reponse_client: tr("Réponse d'un client"),
              decision_attendue: tr('Une décision ou une action est attendue de vous'), reponse_soc: tr('Le SOC vous répond'), incident_resolu: tr('Un incident est résolu') }[k]}</label>
          ))}
        </section>
      )}
      <section className="card section" aria-label={tr("Sessions")}>
        <header className="section-head"><h2>{tr("Sessions actives")}</h2>
          {sessions?.length > 1 && <button type="button" className="small-btn danger" onClick={revokeOthers}>{tr('Fermer les autres sessions')}</button>}</header>
        <p className="muted small">{tr("Une session que vous ne reconnaissez pas ? Fermez-la, puis changez votre mot de passe.")}</p>
        <div className="table-wrap"><table className="grid">
          <thead><tr><th scope="col">{tr("Session")}</th><th scope="col">{tr("Ouverte le")}</th><th scope="col">{tr("Dernière activité")}</th><th scope="col">{tr("Expire le")}</th><th scope="col"><span className="sr-only">{tr("Action")}</span></th></tr></thead>
          <tbody>{sessions?.map((s) => (
            <tr key={s.id} className={s.courante ? 'current' : ''}>
              <td>{s.courante ? <span className="pill ok">{tr('Ce navigateur')}</span> : <span className="muted small">{tr('Autre appareil ou navigateur')}</span>}{s.sso && <span className="pill">SSO</span>}</td>
              <td className="mono small">{formatUtc(s.created_at)}</td><td className="mono small">{formatUtc(s.last_seen_at)}</td><td className="mono small">{formatUtc(s.expires_at)}</td>
              <td>{!s.courante && <button type="button" className="small-btn danger" onClick={() => revoke(s.id)}>{tr("Fermer")}</button>}</td></tr>))}
          </tbody></table></div>
      </section>
    </>
  )
}
