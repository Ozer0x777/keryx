// Internationalisation : le texte source est le français (langue par défaut du plan) ; chaque chaîne passe par t().
// Une chaîne sans traduction s'affiche en français (repli sûr). Les textes d'origine de Wazuh et de MITRE ATT&CK
// restent en anglais, comme le plan le prévoit. Changer de langue recharge la page (aucun état à resynchroniser).
const KEY = 'keryx_lang'
export const LANGS = { fr: 'Français', en: 'English' }

export function getLang() {
  try { const v = localStorage.getItem(KEY); if (v && v in LANGS) return v } catch { /* stockage indisponible */ }
  return 'fr'
}
export function setLang(lang) {
  try { localStorage.setItem(KEY, lang) } catch { /* stockage indisponible */ }
  document.documentElement.lang = lang
  window.location.reload()
}
export function initLang() { document.documentElement.lang = getLang() }

import EN from './i18n.en.js'

export function t(fr, vars) {
  let s = getLang() === 'en' ? (EN[fr] ?? fr) : fr
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v))
  return s
}
