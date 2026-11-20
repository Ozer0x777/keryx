import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { formatUtc } from '../../labels.js'

export default function System() {
  const [s, setS] = useState(null)
  const [error, setError] = useState('')
  const [ret, setRet] = useState(null)
  const load = () => api('/admin/system').then(setS).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])
  const retention = async (dry) => {
    if (!dry && !window.confirm('Supprimer définitivement les alertes brutes arrivées en fin de rétention ? Cette opération est tracée.')) return
    try { setRet(await api('/admin/retention', { method: 'POST', json: { dry_run: dry } })) } catch (e) { setError(e.message) }
  }
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
      <h3>Rétention des alertes brutes</h3>
      <p className="muted small">Seules les alertes brutes des tickets clos, plus anciennes que la durée du client (12 mois par défaut, 6 minimum), sont supprimées. Les tickets, le registre des actions et les pièces sont conservés.</p>
      <div className="row gap"><button type="button" onClick={() => retention(true)}>Simuler</button><button type="button" className="danger" onClick={() => retention(false)}>Purger</button></div>
      {ret && (
        <div role="status">
          <p className="banner ok">{ret.dry_run ? 'Simulation' : 'Purge effectuée'} : {ret.total} alerte(s) {ret.dry_run ? 'concernée(s)' : 'supprimée(s)'}.</p>
          <ul className="small">{ret.items.map((r) => <li key={r.client}>{r.client} : {r.alerts} alerte(s) antérieure(s) au {r.before} ({r.months} mois)</li>)}</ul>
        </div>
      )}
    </section>
  )
}
