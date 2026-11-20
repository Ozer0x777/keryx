import { t as tr } from '../i18n.js'
import { STATUS } from '../labels.js'

const SEVERITY_CLASS = { Critique: 'sev-critique', 'Élevée': 'sev-elevee', Moyenne: 'sev-moyenne', Faible: 'sev-faible' }

export function Severity({ value, prefix = '' }) {
  if (!value) return <span className="muted">—</span>
  return <span className={`badge ${SEVERITY_CLASS[value] || 'sev-faible'}`}>{prefix}{tr(value)}</span>
}

export function Tlp({ value }) {
  const cls = { 'TLP:RED': 'tlp-red', 'TLP:AMBER': 'tlp-amber', 'TLP:AMBER+STRICT': 'tlp-amber', 'TLP:GREEN': 'tlp-green' }[value] || 'tlp-clear'
  return <span className={`tlp ${cls}`}>{value}</span>
}

export function Status({ value }) {
  const s = STATUS[value] || { label: value, color: '#8D97A5' }
  return (
    <span className="status">
      <span className="dot" aria-hidden="true" style={{ background: s.color }} />
      {s.label}
    </span>
  )
}
