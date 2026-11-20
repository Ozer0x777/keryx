import { t as tr } from '../i18n.js'
// Graphiques sans bibliothèque ni ressource externe. Chaque graphique a un équivalent texte (tableau ou libellés).
export function BarList({ rows, colors = {}, label }) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <ul className="barlist" aria-label={label}>
      {rows.map((r) => (
        <li key={r.label}>
          <span className="bl-label">{tr(r.label)}</span>
          <span className="bl-track" aria-hidden="true"><span className="bl-fill" style={{ width: `${(100 * r.value) / max}%`, background: colors[r.key || r.label] || 'var(--accent)' }} /></span>
          <span className="bl-value mono">{r.value}</span>
        </li>
      ))}
    </ul>
  )
}

// Colonnes jumelées par jour : créés (bleu) et clos (vert).
export function TrendChart({ data }) {
  const W = 720, H = 180, pad = { l: 28, r: 8, t: 10, b: 22 }
  const max = Math.max(1, ...data.flatMap((d) => [d.created, d.closed]))
  const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b
  const step = iw / Math.max(1, data.length)
  const bw = Math.max(1.5, Math.min(10, step / 2.6))
  const y = (v) => pad.t + ih - (ih * v) / max
  const tick = Math.max(1, Math.ceil(data.length / 6))
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={tr("Tickets créés et clos par jour")}>
        {[0, 0.5, 1].map((f) => (
          <g key={f}><line x1={pad.l} x2={W - pad.r} y1={y(max * f)} y2={y(max * f)} stroke="#E3E6EB" /><text x={pad.l - 4} y={y(max * f) + 4} textAnchor="end" fontSize="10" fill="#5B6472">{Math.round(max * f)}</text></g>
        ))}
        {data.map((d, i) => {
          const x = pad.l + i * step + step / 2
          return (
            <g key={d.date}>
              {d.created > 0 && <rect x={x - bw} y={y(d.created)} width={bw} height={pad.t + ih - y(d.created)} fill="#1F5FD1"><title>{`${d.date} : ${d.created} créé(s)`}</title></rect>}
              {d.closed > 0 && <rect x={x} y={y(d.closed)} width={bw} height={pad.t + ih - y(d.closed)} fill="#1B6B3A"><title>{`${d.date} : ${d.closed} clos`}</title></rect>}
              {i % tick === 0 && <text x={x} y={H - 6} textAnchor="middle" fontSize="10" fill="#5B6472">{d.date.slice(5)}</text>}
            </g>
          )
        })}
      </svg>
      <figcaption className="muted small"><span className="key" style={{ background: '#1F5FD1' }} /> {tr("créés")} <span className="key" style={{ background: '#1B6B3A' }} /> {tr("clos")}</figcaption>
      <details><summary className="small">{tr("Voir les valeurs en tableau")}</summary>
        <table className="grid"><thead><tr><th scope="col">{tr("Jour")}</th><th scope="col" className="num">{tr("Créés")}</th><th scope="col" className="num">{tr("Clos")}</th></tr></thead>
          <tbody>{data.filter((d) => d.created || d.closed).map((d) => <tr key={d.date}><td className="mono">{d.date}</td><td className="num">{d.created}</td><td className="num">{d.closed}</td></tr>)}</tbody></table>
      </details>
    </figure>
  )
}
