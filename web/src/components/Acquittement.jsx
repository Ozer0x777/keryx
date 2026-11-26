import { t as tr } from '../i18n.js'

// Délai d'acquittement (ADR-0032) : de la détection Wazuh à la première action humaine de l'équipe.
export const fmtMin = (m) => (m == null ? '—' : m < 60 ? `${Math.round(m)} min` : m < 2880 ? `${Math.round(m / 6) / 10} h` : `${Math.round(m / 144) / 10} j`)

export function AcquittementTable({ data, caption }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}><table className="grid">
      <caption className="sr-only">{caption}</caption>
      <thead><tr><th scope="col">{tr('Criticité')}</th><th scope="col">{tr('Délai moyen')}</th><th scope="col">{tr('9 sur 10 en moins de')}</th><th scope="col">{tr('Acquittés')}</th><th scope="col">{tr('Pas encore acquittés')}</th></tr></thead>
      <tbody>{Object.entries(data).map(([crit, v]) => (
        <tr key={crit}><th scope="row">{tr(crit)}</th><td>{fmtMin(v.moyenne_min)}</td><td>{fmtMin(v.p90_min)}</td><td>{v.acquittes}</td><td>{v.non_acquittes}</td></tr>
      ))}</tbody>
    </table></div>
  )
}
