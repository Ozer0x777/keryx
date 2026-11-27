import { useEffect } from 'react'

// Raccourcis clavier d'une page (S13) : une touche simple, ignorée quand on tape dans un champ, un éditeur ou une liste
// déroulante, ou avec Ctrl, Alt ou Méta (les raccourcis du navigateur restent libres).
export function useShortcuts(map, enabled = true) {
  useEffect(() => {
    if (!enabled) return undefined
    const onKey = (e) => {
      if (e.ctrlKey || e.altKey || e.metaKey || e.defaultPrevented) return
      const el = e.target
      if (el.closest?.('input, textarea, select, [contenteditable=true], [contenteditable=""], dialog[open]')) return
      const fn = map[e.key]
      if (fn) { e.preventDefault(); fn(e) }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [map, enabled])
}
