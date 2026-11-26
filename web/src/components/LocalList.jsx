import { useState } from 'react'
import { t as tr } from '../i18n.js'
import { localPage } from '../queue.js'
import Pager from './Pager.jsx'

// Recherche et pages d'une liste chargée en entier (comptes, revue des comptes, table MITRE) : 50 lignes par page,
// retour à la page 1 quand la recherche change. Rend la zone de recherche, le compte, la barre de pages et les lignes.
export function useLocalList(items, texte, label) {
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const { info, total, rows } = localPage(items, texte, q, page)
  const search = (
    <div className="row wrap gap between list-bar">
      <label className="filter grow">{tr('Rechercher')}
        <input type="search" value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} />
      </label>
      {items && <p className="list-count" role="status">{total > rows.length
        ? tr('Lignes {from} à {to} sur {total}', { from: info.from, to: info.to, total })
        : tr('{n} ligne(s)', { n: total })}</p>}
    </div>
  )
  const pager = total > info.size && <Pager info={info} label={label} onPage={setPage} />
  return { rows: items ? rows : null, search, pager }
}
