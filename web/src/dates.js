// Dates « jour » des formulaires (AAAA-MM-JJ), en UTC comme toutes les dates de Keryx.
// Tout est construit ET formaté en UTC : un 1er du mois bâti en heure locale puis converti par toISOString()
// devenait le dernier jour du mois précédent à l'est de Greenwich (et l'inverse n'était juste que par chance à l'ouest).
export const isoDay = (d) => d.toISOString().slice(0, 10)

export const monthStartUtc = (now = new Date()) => isoDay(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)))

// Heure courante « hh:mm UTC » des retours d'action (« Enregistré à 14:02 UTC »), cohérente avec formatUtc().
export const utcClock = (d = new Date()) => `${d.toISOString().slice(11, 16)} UTC`

// Champs <input type="datetime-local"> : Keryx affiche toutes ses dates en UTC, la saisie l'est donc aussi
// (le libellé du champ le dit). La valeur « AAAA-MM-JJTHH:MM » est lue et produite en UTC, jamais en heure du poste.
export const utcInputNow = (d = new Date()) => d.toISOString().slice(0, 16)
export const isoToUtcInput = (iso) => (iso ? new Date(iso).toISOString().slice(0, 16) : '')
export const utcInputToIso = (value) => (value ? new Date(`${value.slice(0, 16)}:00Z`).toISOString() : null)

// Temps restant avant une échéance (ou écoulé depuis) : { late, days, hours, minutes }. Sert à l'en-tête de la fiche
// ticket (« Qualifier avant … · dans 2 h 05 »). `now` est injectable pour les tests.
export function untilUtc(iso, now = Date.now()) {
  const delta = new Date(iso).getTime() - now
  const total = Math.floor(Math.abs(delta) / 60000)
  return { late: delta < 0, days: Math.floor(total / 1440), hours: Math.floor((total % 1440) / 60), minutes: total % 60 }
}
