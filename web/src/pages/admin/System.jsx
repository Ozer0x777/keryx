import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { formatUtc } from '../../labels.js'

export default function System() {
  const [s, setS] = useState(null)
  const [error, setError] = useState('')
  const load = () => api('/admin/system').then(setS).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])
  const tone = (v) => (['ok', 'disponible', 'configuré'].includes(v) ? 'ok' : v === 'non configuré' ? '' : 'danger')
  const rows = s ? [
    ['Base de données', s.database], ['Courriel (SMTP)', s.smtp], ['Antivirus (ClamAV)', s.clamav], ['Export syslog', s.syslog],
  ] : []
  return (
    <section className="card section" aria-label="État du système">
      <header className="section-head"><h2>État du système</h2><button type="button" onClick={load}>Actualiser</button></header>
      {error && <p className="error" role="alert">{error}</p>}
      {s && <>
        <p className="muted small">Relevé du {formatUtc(s.generated_at)}</p>
        <dl className="status-list">
          {rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd><span className={`pill ${tone(v)}`}>{v}</span></dd></div>)}
          <div><dt>Espace disque des pièces</dt><dd>{s.disk_free_mb} Mo libres sur {s.disk_total_mb} Mo</dd></div>
          <div><dt>Notifications en échec (24 h)</dt><dd><span className={`pill ${s.notifications_failed_24h ? 'danger' : 'ok'}`}>{s.notifications_failed_24h}</span></dd></div>
          <div><dt>Sources Wazuh muettes</dt><dd><span className={`pill ${s.silent_sources ? 'warn' : 'ok'}`}>{s.silent_sources}</span></dd></div>
        </dl>
      </>}
    </section>
  )
}
