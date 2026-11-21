import { useEffect, useRef, useState } from 'react'
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
// Le dessin prend la largeur réelle de son cadre (1 unité = 1 px) : les libellés d'axes restent à 12 px quelle que
// soit la taille de l'écran, au lieu de rétrécir avec un dessin mis à l'échelle.
export function TrendChart({ data }) {
  const box = useRef(null)
  const [W, setW] = useState(720)
  useEffect(() => {
    const el = box.current
    if (!el || typeof ResizeObserver === 'undefined') return undefined
    const ro = new ResizeObserver(([entry]) => setW(Math.max(260, Math.round(entry.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const H = 200, pad = { l: 34, r: 8, t: 12, b: 28 }
  const max = Math.max(1, ...data.flatMap((d) => [d.created, d.closed]))
  const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b
  const step = iw / Math.max(1, data.length)
  const bw = Math.max(1.5, Math.min(10, step / 2.6))
  const y = (v) => pad.t + ih - (ih * v) / max
  const tick = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(iw / 64))))   // une date tous les 64 px au plus
  const marks = [...new Set([0, Math.ceil(max / 2), max])]                               // graduations entières, sans doublon
  return (
    <figure className="trend">
      <div ref={box}>
      <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label={tr("Tickets créés et clos par jour")}>
        {marks.map((v) => (
          <g key={v}><line x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} stroke="#E3E6EB" /><text x={pad.l - 6} y={y(v) + 4} textAnchor="end" fontSize="12" fill="#5B6472">{v}</text></g>
        ))}
        {data.map((d, i) => {
          const x = pad.l + i * step + step / 2
          return (
            <g key={d.date}>
              {d.created > 0 && <rect x={x - bw} y={y(d.created)} width={bw} height={pad.t + ih - y(d.created)} fill="#1F5FD1"><title>{`${d.date} : ${d.created} créé(s)`}</title></rect>}
              {d.closed > 0 && <rect x={x} y={y(d.closed)} width={bw} height={pad.t + ih - y(d.closed)} fill="#1B6B3A"><title>{`${d.date} : ${d.closed} clos`}</title></rect>}
              {i % tick === 0 && <text x={x} y={H - 8} textAnchor="middle" fontSize="12" fill="#5B6472">{d.date.slice(5)}</text>}
            </g>
          )
        })}
      </svg>
      </div>
      <figcaption className="muted small"><span className="key" style={{ background: '#1F5FD1' }} /> {tr("créés")} <span className="key" style={{ background: '#1B6B3A' }} /> {tr("clos")}</figcaption>
      <details><summary className="small">{tr("Voir les valeurs en tableau")}</summary>
        <table className="grid"><thead><tr><th scope="col">{tr("Jour")}</th><th scope="col" className="num">{tr("Créés")}</th><th scope="col" className="num">{tr("Clos")}</th></tr></thead>
          <tbody>{data.filter((d) => d.created || d.closed).map((d) => <tr key={d.date}><td className="mono">{d.date}</td><td className="num">{d.created}</td><td className="num">{d.closed}</td></tr>)}</tbody></table>
      </details>
    </figure>
  )
}
