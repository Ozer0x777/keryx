import { useEffect, useRef } from 'react'

// Onglets de la fiche ticket (motif WAI-ARIA « Tabs » : tablist, tab, tabpanel). Activation automatique : les flèches
// déplacent le focus et changent d'onglet, Début et Fin vont aux extrémités, seul l'onglet actif est dans l'ordre de
// tabulation. Les panneaux inactifs restent montés (attribut `hidden`) : une saisie en cours n'est pas perdue
// en changeant d'onglet.
export function TabBar({ tabs, active, onSelect, label, idBase }) {
  const list = useRef(null)
  useEffect(() => { list.current?.querySelector('.tab.on')?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' }) }, [active])
  const move = (e) => {
    // L'onglet de départ est celui qui a le focus : l'URL, elle, ne suit qu'après le rendu (flèches enchaînées vite).
    const els = [...list.current.querySelectorAll('[role=tab]')]
    const focused = els.indexOf(document.activeElement)
    const i = focused >= 0 ? focused : tabs.findIndex((x) => x.id === active)
    const next = { ArrowRight: (i + 1) % tabs.length, ArrowLeft: (i - 1 + tabs.length) % tabs.length, Home: 0, End: tabs.length - 1 }[e.key]
    if (next === undefined) return
    e.preventDefault()
    onSelect(tabs[next].id)
    els[next]?.focus()
  }
  return (
    <div className="tabs ticket-tabs" role="tablist" aria-label={label} ref={list} onKeyDown={move}>
      {tabs.map((x) => (
        <button type="button" role="tab" key={x.id} id={`${idBase}-tab-${x.id}`} aria-selected={active === x.id}
          aria-controls={`${idBase}-panel-${x.id}`} tabIndex={active === x.id ? 0 : -1}
          className={`tab${active === x.id ? ' on' : ''}`} onClick={() => onSelect(x.id)}>
          {x.label}{x.badge}
        </button>
      ))}
    </div>
  )
}

export function TabPanel({ id, idBase, active, children }) {
  return (
    <div role="tabpanel" id={`${idBase}-panel-${id}`} aria-labelledby={`${idBase}-tab-${id}`} hidden={!active}>
      {children}
    </div>
  )
}
