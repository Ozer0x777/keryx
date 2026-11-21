import { t as tr } from '../../i18n.js'
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
    if (!dry && !window.confirm(tr('Supprimer définitivement les alertes brutes arrivées en fin de rétention ? Cette opération est tracée.'))) return
    try { setRet(await api('/admin/retention', { method: 'POST', json: { dry_run: dry } })) } catch (e) { setError(e.message) }
  }
  // Les valeurs d'état viennent du serveur, en français : on les compare telles quelles (traduites à l'affichage seulement).
  const tone = (v) => (['ok', 'disponible', 'configuré'].includes(v) ? 'ok' : v === 'non configuré' ? '' : 'danger')
  // Libellés sources (français) : traduits à l'affichage par tr(k).
  const rows = s ? [
    ['Base de données', s.database], ['Courriel (SMTP)', s.smtp], ['Antivirus (ClamAV)', s.clamav], ['Export syslog', s.syslog],
  ] : []
  return (
    <section className="card section" aria-label={tr("État du système")}>
      <header className="section-head"><h2>{tr("État du système")}</h2><button type="button" onClick={load}>{tr("Actualiser")}</button></header>
      {error && <p className="error" role="alert">{error}</p>}
      {s && <>
        <p className="muted small">{tr('Relevé du {when}', { when: formatUtc(s.generated_at) })}</p>
        <dl className="status-list">
          {rows.map(([k, v]) => <div key={k}><dt>{tr(k)}</dt><dd><span className={`pill ${tone(v)}`}>{tr(v)}</span></dd></div>)}
          <div><dt>{tr("Stockage des pièces")}</dt><dd><span className={`pill ${s.storage.includes('injoignable') ? 'danger' : 'ok'}`}>{tr(s.storage)}</span>{s.disk_free_mb != null && ` · ${tr('{free} Mo libres sur {total} Mo', { free: s.disk_free_mb, total: s.disk_total_mb })}`}</dd></div>
          <div><dt>{tr("Notifications en échec (24 h)")}</dt><dd><span className={`pill ${s.notifications_failed_24h ? 'danger' : 'ok'}`}>{s.notifications_failed_24h}</span></dd></div>
          <div><dt>{tr("Sources Wazuh muettes")}</dt><dd><span className={`pill ${s.silent_sources ? 'warn' : 'ok'}`}>{s.silent_sources}</span></dd></div>
        </dl>
      </>}
      <h3>{tr("Rétention des alertes brutes")}</h3>
      <p className="muted small">{tr("Seules les alertes brutes des tickets clos, plus anciennes que la durée du client (12 mois par défaut, 6 minimum), sont supprimées. Les tickets, le registre des actions et les pièces sont conservés.")}</p>
      <div className="row gap"><button type="button" onClick={() => retention(true)}>{tr("Simuler")}</button><button type="button" className="danger" onClick={() => retention(false)}>{tr("Purger")}</button></div>
      {ret && (
        <div role="status">
          <p className="banner ok">{ret.dry_run ? tr('Simulation') : tr('Purge effectuée')} : {ret.total} {tr('alerte(s)')} {ret.dry_run ? tr('concernée(s)') : tr('supprimée(s)')}.</p>
          <ul className="small">{ret.items.map((r) => <li key={r.client}>{tr('{client} : {n} alerte(s) antérieure(s) au {before} ({months} mois)', { client: r.client, n: r.alerts, before: r.before, months: r.months })}</li>)}</ul>
        </div>
      )}
    </section>
  )
}
