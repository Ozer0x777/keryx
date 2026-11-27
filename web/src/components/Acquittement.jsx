import { t as tr } from '../i18n.js'
import { dureeLisible } from '../dates.js'

// Délai d'acquittement (ADR-0032) : de la détection Wazuh à la première action humaine de l'équipe.
export const fmtMin = (m) => (m == null ? '—' : dureeLisible(m * 60))

export function AcquittementTable({ data, caption }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}><table className="grid">
      <caption className="sr-only">{caption}</caption>
      <thead><tr><th scope="col">{tr('Criticité')}</th><th scope="col">{tr('Délai moyen')}</th><th scope="col">{tr('9 sur 10 en moins de')}</th><th scope="col">{tr('Acquittés')}</th><th scope="col">{tr('Pas encore acquittés')}</th></tr></thead>
      <tbody>{Object.entries(data).map(([crit, v]) => (
        <tr key={crit}><th scope="row">{tr(crit)}</th><td>{fmtMin(v.moyenne_min)}</td><td>{fmtMin(v.p90_min)}</td><td>{v.acquittes}</td><td>{v.non_acquittes}</td></tr>
      ))}</tbody>
    </table>
    {Object.values(data).some((v) => v.horloge_en_avance) && (
      <p className="field-hint">{tr("{n} ticket(s) acquitté(s) avant leur heure de détection : l'horloge du manager Wazuh avance sur Keryx (à mettre à l'heure, NTP). Leur délai est compté 0.", { n: Object.values(data).reduce((a, v) => a + (v.horloge_en_avance || 0), 0) })}</p>
    )}
    </div>
  )
}
