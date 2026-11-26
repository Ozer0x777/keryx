import { useRef } from 'react'
import { t as tr } from '../i18n.js'

// Barre de pages commune aux listes longues (tickets, parc d'agents…) : première, précédente, « Page X sur Y »,
// suivante, dernière, et taille de page. La page vit dans l'URL de l'écran qui l'utilise ; `info` vient de pageInfo().
export default function Pager({ info, label, onPage, perPage, perPageOptions, onPerPage, perPageLabel }) {
  // Arrivé à la première ou à la dernière page, le bouton activé se désactive : le focus irait sur la page entière.
  // Il est posé sur l'indication de page, qui reste dans la barre (WCAG 2.4.3).
  const here = useRef(null)
  const go = (n) => {
    onPage(n)
    if (n <= 1 || n >= info.pages) setTimeout(() => here.current?.focus(), 0)
  }
  return (
    <nav className="pager row wrap gap" aria-label={label}>
      <button type="button" className="small-btn" onClick={() => go(1)} disabled={info.page <= 1}>{tr('Première')}</button>
      <button type="button" className="small-btn" onClick={() => go(info.page - 1)} disabled={info.page <= 1}>{tr('Précédente')}</button>
      <span ref={here} tabIndex={-1} aria-current="page">{tr('Page {p} sur {n}', { p: info.page, n: info.pages })}</span>
      <button type="button" className="small-btn" onClick={() => go(info.page + 1)} disabled={info.page >= info.pages}>{tr('Suivante')}</button>
      <button type="button" className="small-btn" onClick={() => go(info.pages)} disabled={info.page >= info.pages}>{tr('Dernière')}</button>
      {onPerPage && (
        <label className="row gap">{perPageLabel}
          <select value={perPage} onChange={(e) => onPerPage(e.target.value)}>
            {perPageOptions.map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      )}
    </nav>
  )
}
