import { t as tr } from '../i18n.js'

// Indicateurs minimaux de PDIS IV.5.1.e, f, g que Keryx produit (tickets, notifications, comptes du portail), pour
// les comités opérationnels et stratégiques. Ceux des évènements, des collecteurs et des règles relèvent de Wazuh.
const h = (v) => (v == null ? '—' : `${v} h`)
const mn = (v) => (v == null ? '—' : v < 120 ? `${Math.round(v)} min` : `${Math.round(v / 6) / 10} h`)
const CRIT = ['Critique', 'Élevée', 'Moyenne', 'Faible']
const mo = (o) => (o == null ? '—' : o < 1048576 ? `${Math.round(o / 1024)} Kio` : o < 1073741824 ? `${Math.round(o / 104857.6) / 10} Mio` : `${Math.round(o / 107374182.4) / 10} Gio`)

function Tableau({ label, head, rows }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={label}><table className="grid">
      <thead><tr>{head.map((x) => <th key={x} scope="col">{x}</th>)}</tr></thead>
      <tbody>{rows.length === 0 ? <tr><td colSpan={head.length} className="muted">{tr('Aucune donnée sur la période.')}</td></tr>
        : rows.map((r, i) => <tr key={i}>{r.map((c, j) => (j === 0 ? <th key={j} scope="row">{c}</th> : <td key={j}>{c}</td>))}</tr>)}</tbody>
    </table></div>
  )
}

export default function IndicateursPdis({ d }) {
  if (!d) return null
  const r = d.resolution_h
  return (
    <section className="card section" aria-label={tr('Indicateurs PDIS')}>
      <h2>{tr('Indicateurs PDIS (IV.5.1)')}</h2>
      <p className="muted small">{tr("Indicateurs que Keryx produit pour les comités. Ceux des évènements, des collecteurs et des règles de détection se lisent dans Wazuh.")}</p>
      <h3>{tr('Durée entre création et clôture')}</h3>
      <p>{tr('Minimale {a}, moyenne {b}, maximale {c} ({n} ticket(s) clos)', { a: h(r.min), b: h(r.moyenne), c: h(r.max), n: r.n })}</p>
      <h3>{tr('Délai entre détection et notification du client, par gravité')}</h3>
      <Tableau label={tr('Délai entre détection et notification')} head={[tr('Criticité'), tr('Minimal'), tr('Moyen'), tr('Maximal'), tr('Tickets')]}
        rows={CRIT.filter((c) => d.detection_notification_min[c]).map((c) => { const s = d.detection_notification_min[c]; return [tr(c), mn(s.min), mn(s.moyenne), mn(s.max), s.n] })} />
      <h3>{tr('Par mois')}</h3>
      <Tableau label={tr('Indicateurs par mois')} head={[tr('Mois'), tr('Créés'), tr('Clos'), tr('Avérés'), tr('Alertes reçues'), tr('Ouverts cumulés (C / É / M / F)'), tr('Résolution moyenne')]}
        rows={d.par_mois.map((m) => [m.mois, m.crees, m.clos, m.averes, m.alertes, CRIT.map((c) => m.ouverts_cumules[c]).join(' / '), h(m.resolution_moyenne_h)])} />
      <h3>{tr('Durée moyenne de qualification, par typologie et gravité')}</h3>
      <Tableau label={tr('Durée moyenne de qualification')} head={[tr('Typologie'), ...CRIT.map((c) => tr(c))]}
        rows={Object.entries(d.qualification_par_typologie_h).map(([k, v]) => [tr(k), ...CRIT.map((c) => h(v[c]))])} />
      <h3>{tr('Les 20 règles les plus déclenchées')}</h3>
      <Tableau label={tr('Règles les plus déclenchées')} head={[tr('Règle'), tr('Description'), tr('Alertes')]}
        rows={d.regles_les_plus_declenchees.map((x) => [x.regle, x.description, x.alertes])} />
      <h3>{tr('Envoi des notifications')}</h3>
      <Tableau label={tr('Envoi des notifications par mois')} head={[tr('Mois'), tr('Envoyées'), tr('Échecs'), tr('Réussite')]}
        rows={(d.notifications_par_mois || []).map((m) => [m.mois, m.envoyees, m.echecs, m.reussite_pourcent == null ? '—' : `${m.reussite_pourcent} %`])} />
      {d.capacite && <>
        <h3>{tr('Capacité du stockage')}</h3>
        <p>{tr('Base des tickets et des notifications : {b}.', { b: mo(d.capacite.base_octets) })}{' '}
          {d.capacite.disque_pieces
            ? tr('Disque des pièces : {p} % rempli, {l} libres sur {t}.', { p: d.capacite.disque_pieces.remplissage_pourcent, l: mo(d.capacite.disque_pieces.libre_octets), t: mo(d.capacite.disque_pieces.total_octets) })
            : tr('Pièces en stockage objet : capacité suivie par son propre outil.')}</p>
      </>}
      <h3>{tr('Portail des clients')}</h3>
      <p>{tr('{n} compte(s) Client actif(s).', { n: d.portail.comptes_actifs })}</p>
      <Tableau label={tr('Comptes et authentifications du portail')} head={[tr('Mois'), tr('Comptes créés'), tr('Connexions réussies'), tr('Connexions échouées')]}
        rows={d.portail.authentifications_par_mois.map((a) => [a.mois, d.portail.comptes_crees_par_mois[a.mois] || 0, a.reussies, a.echouees])} />
    </section>
  )
}
