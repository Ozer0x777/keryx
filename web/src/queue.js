// File de triage : l'état de la liste (filtres, tri, vue) vit dans l'URL (?status=…&sort=…), pour qu'il soit restauré
// au retour d'un ticket, partageable et conservé au rechargement. Fonctions pures, testées par npm test.
export const DEFAULTS = { status: '', severity: '', client: '', rex_en_attente: false, critical_unassigned: false, awaiting_client: false, incomplete: false, q: '', assignee: '', overdue: false, sort: 'created', order: 'desc', page: '1', per_page: '50' }
const BOOLEANS = ['rex_en_attente', 'overdue', 'critical_unassigned', 'awaiting_client', 'incomplete']
export const SORTS = ['created', 'updated', 'detected', 'ref', 'status', 'occurrences', 'criticite', 'gravite']
export const SEVERITIES = ['Critique', 'Élevée', 'Moyenne', 'Faible']   // ordre de tri métier, du plus grave au moins grave
export const PER_PAGE = ['25', '50', '100']                              // tickets par page (l'API en accepte 500 au plus)
export const OPEN_STATUSES = 'nouveau,en_evaluation,en_reponse'
export const TO_QUALIFY = 'nouveau,en_evaluation'

// Lit les filtres depuis les paramètres d'URL ; toute valeur inconnue retombe sur la valeur par défaut (jamais d'erreur 422).
export function filtersFromSearch(search) {
  const sp = search instanceof URLSearchParams ? search : new URLSearchParams(search || '')
  const f = { ...DEFAULTS }
  for (const key of Object.keys(DEFAULTS)) {
    const v = sp.get(key)
    if (v === null) continue
    f[key] = BOOLEANS.includes(key) ? (v === '1' || v === 'true') : v.slice(0, 200)
  }
  if (!SORTS.includes(f.sort)) f.sort = DEFAULTS.sort
  if (f.order !== 'asc' && f.order !== 'desc') f.order = DEFAULTS.order
  if (f.severity && !SEVERITIES.includes(f.severity)) f.severity = ''
  if (!PER_PAGE.includes(f.per_page)) f.per_page = DEFAULTS.per_page
  if (!/^[1-9][0-9]{0,5}$/.test(f.page)) f.page = DEFAULTS.page
  return f
}

// Pagination de la liste : page demandée ramenée dans les bornes, première et dernière ligne affichées (comptées à
// partir de 1) et décalage à demander à l'API. Sans ticket : une seule page, vide.
export function pageInfo(total, page, perPage) {
  const size = Math.max(1, Number(perPage) || Number(DEFAULTS.per_page))
  const pages = Math.max(1, Math.ceil((Number(total) || 0) / size))
  const current = Math.min(Math.max(1, Number(page) || 1), pages)
  const offset = (current - 1) * size
  return { page: current, pages, size, offset, from: total ? offset + 1 : 0, to: Math.min(offset + size, Number(total) || 0) }
}

// Écrit les filtres dans l'URL : seules les valeurs qui diffèrent du défaut y figurent (URL courte et stable).
export function filtersToSearch(filters) {
  const out = {}
  for (const key of Object.keys(DEFAULTS)) {
    const v = filters[key]
    if (v === undefined || v === null || v === DEFAULTS[key]) continue
    out[key] = v === true ? '1' : String(v)
  }
  return out
}

// Cartes de chiffres = filtres rapides. Chacune fixe les sept critères d'état ; les autres (recherche, client,
// assigné, tri) sont conservés. Aucune carte ne touche à l'assigné : les vues de priorisation (ADR-0025) ont chacune
// leur propre critère, pour ne jamais laisser un filtre d'assigné caché derrière une carte.
// Une carte est « enfoncée » quand ces critères valent exactement les siens.
const CARD_RESET = { status: '', severity: '', overdue: false, rex_en_attente: false, critical_unassigned: false, awaiting_client: false, incomplete: false }
export const cardPatch = (patch) => ({ ...CARD_RESET, ...patch })
export const cardActive = (filters, patch) => Object.entries(cardPatch(patch)).every(([k, v]) => filters[k] === v)

// Dernière file consultée (dans cet onglet) : le fil d'Ariane d'une fiche y ramène, filtres compris.
const KEY = 'keryx_file'
export function rememberQueue(search) {
  try { sessionStorage.setItem(KEY, String(search || '')) } catch { /* stockage indisponible */ }
}
export function queuePath() {
  let qs = ''
  try { qs = sessionStorage.getItem(KEY) || '' } catch { /* stockage indisponible */ }
  qs = qs.replace(/^\?/, '')
  return qs ? `/tickets?${qs}` : '/tickets'
}

// Liste chargée en entier mais affichée par pages (comptes, table MITRE…) : filtre par texte (sans tenir compte de la
// casse) puis découpe. `texte` donne le texte cherchable d'une ligne.
export function localPage(items, texte, q, page, perPage = 50) {
  const needle = (q || '').trim().toLowerCase()
  const filtered = (items || []).filter((x) => !needle || texte(x).toLowerCase().includes(needle))
  const info = pageInfo(filtered.length, page, perPage)
  return { info, total: filtered.length, rows: filtered.slice(info.offset, info.offset + info.size) }
}
