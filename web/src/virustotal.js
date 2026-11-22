// Recherche d'empreinte sur VirusTotal (ADR-0022) : logique pure de l'interface, testée sans navigateur.
// Seule une empreinte part vers VirusTotal ; ce qui en revient est une donnée non fiable, déjà ramenée par le serveur
// à des compteurs et à du texte borné. Ici : forme d'une empreinte, lecture d'un résultat, lien vers la fiche du site.

// SHA-256 (64) ou SHA-1 (40), en minuscules. MD5 n'est pas accepté (collisions : le rapport pourrait être celui d'un autre fichier).
const HASH = /^(?:[0-9a-f]{64}|[0-9a-f]{40})$/
export const normalizeHash = (value) => String(value ?? '').trim().toLowerCase()
export const isHash = (value) => typeof value === 'string' && HASH.test(value)
export const shortHash = (h) => (isHash(h) ? `${h.slice(0, 12)}…${h.slice(-6)}` : '')

const count = (v) => (Number.isInteger(v) && v >= 0 ? v : 0)

// Lecture d'une recherche enregistrée. `tone` est la classe de la pastille : « danger », « warn » ou neutre ('').
// Il n'y a JAMAIS de ton « ok » : ni un fichier inconnu de VirusTotal, ni un fichier sans détection n'est présenté
// comme sain.
export function verdict(lookup) {
  const stats = lookup?.summary?.stats || {}
  const malicious = count(stats.malicious), suspicious = count(stats.suspicious)
  const total = Math.max(count(stats.total), malicious + suspicious)
  if (lookup?.status !== 'trouve') return { kind: 'inconnu', tone: '', malicious: 0, suspicious: 0, total: 0 }
  if (malicious > 0) return { kind: 'malveillant', tone: 'danger', malicious, suspicious, total }
  if (suspicious > 0) return { kind: 'suspect', tone: 'warn', malicious, suspicious, total }
  return { kind: 'aucune_detection', tone: '', malicious, suspicious, total }
}

// Lien vers la fiche du fichier sur le site de VirusTotal : accepté seulement s'il est exactement celui que Keryx
// construit (hôte officiel + l'empreinte de la recherche). Rien d'autre ne devient un lien.
export function vtLink(lookup) {
  const h = lookup?.hash
  return isHash(h) && lookup.url === `https://www.virustotal.com/gui/file/${h}` ? lookup.url : null
}

// Dernière recherche faite pour une source donnée (les recherches arrivent de la plus récente à la plus ancienne).
export const lastFor = (lookups, pred) => (lookups || []).find(pred) || null
