// Thème de l'interface (A12) : « clair » par défaut, « sombre », ou « systeme » (suit prefers-color-scheme).
// Choix propre à ce navigateur (localStorage), comme la langue ; rien n'est envoyé au serveur.
const KEY = 'keryx_theme'
export const THEMES = ['clair', 'sombre', 'systeme']
const media = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null

export function getTheme() {
  try { const v = localStorage.getItem(KEY); return THEMES.includes(v) ? v : 'clair' } catch { return 'clair' }
}

function apply() {
  const t = getTheme()
  const dark = t === 'sombre' || (t === 'systeme' && media?.matches)
  if (dark) document.documentElement.setAttribute('data-theme', 'dark')
  else document.documentElement.removeAttribute('data-theme')
}

export function setTheme(t) {
  try { if (t === 'clair') localStorage.removeItem(KEY); else localStorage.setItem(KEY, t) } catch { /* stockage refusé : thème de la session seulement */ }
  apply()
}

export function initTheme() {
  apply()
  media?.addEventListener?.('change', apply)
  // Impression et PDF toujours en clair : texte sombre sur papier blanc.
  window.addEventListener('beforeprint', () => document.documentElement.removeAttribute('data-theme'))
  window.addEventListener('afterprint', apply)
}
