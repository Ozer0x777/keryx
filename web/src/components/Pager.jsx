import { t as tr } from '../i18n.js'

// Barre de pages commune aux listes longues (tickets, parc d'agents…) : première, précédente, « Page X sur Y »,
// suivante, dernière, et taille de page. La page vit dans l'URL de l'écran qui l'utilise ; `info` vient de pageInfo().
export default function Pager({ info, label, onPage, perPage, perPageOptions, onPerPage, perPageLabel }) {
  return (
    <nav className="pager row wrap gap" aria-label={label}>
      <button type="button" className="small-btn" onClick={() => onPage(1)} disabled={info.page <= 1}>{tr('Première')}</button>
      <button type="button" className="small-btn" onClick={() => onPage(info.page - 1)} disabled={info.page <= 1}>{tr('Précédente')}</button>
      <span aria-current="page">{tr('Page {p} sur {n}', { p: info.page, n: info.pages })}</span>
      <button type="button" className="small-btn" onClick={() => onPage(info.page + 1)} disabled={info.page >= info.pages}>{tr('Suivante')}</button>
      <button type="button" className="small-btn" onClick={() => onPage(info.pages)} disabled={info.page >= info.pages}>{tr('Dernière')}</button>
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
