import { Link } from 'react-router-dom'
import { t as tr } from '../i18n.js'

// Parc d'agents Wazuh dans le pilotage et le rapport périodique (ADR-0030) : état courant et disponibilité moyenne sur
// la période. Rien n'est affiché si aucun relevé n'existe pour le périmètre.
export default function ParcSummary({ parc, links = true }) {
  if (!parc) return null
  const s = parc.by_status
  return (
    <section className="card section" aria-label={tr("Parc d'agents Wazuh")}>
      <h2>{tr("Parc d'agents Wazuh")}</h2>
      <dl className="kv">
        <dt>{tr('Agents')}</dt><dd>{parc.agents}</dd>
        <dt>{tr('Actifs')}</dt><dd>{s.active || 0}</dd>
        <dt>{tr('Déconnectés')}</dt><dd>{s.disconnected || 0}{parc.down24 ? <> <span className="pill danger">{tr('{n} depuis plus de 24 h', { n: parc.down24 })}</span></> : null}</dd>
        <dt>{tr('Jamais connectés ou en attente')}</dt><dd>{(s.never_connected || 0) + (s.pending || 0)}</dd>
        <dt>{tr('Versions en retard')}</dt><dd>{parc.outdated}</dd>
        <dt>{tr('Disponibilité moyenne sur la période')}</dt><dd>{parc.availability_percent == null ? '—' : `${parc.availability_percent} %`}</dd>
      </dl>
      {parc.least_available.length > 0 && (
        <>
          <h3>{tr('Agents les moins disponibles')}</h3>
          <ul className="plain-list">
            {parc.least_available.map((a) => (
              <li key={`${a.client}-${a.agent}`}>
                {links ? <Link to={`/parc?client=${encodeURIComponent(a.client)}&agent=${encodeURIComponent(a.agent)}`}>{a.name}</Link> : a.name}
                {' '}<span className="muted small mono">{a.client} · {a.agent}</span> : {a.availability} %
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="muted small">{tr("Temps passé actif sur le temps observé par Keryx ; un agent jamais connecté ou en attente n'est pas compté.")}</p>
    </section>
  )
}
