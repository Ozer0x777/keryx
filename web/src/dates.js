// Dates « jour » des formulaires (AAAA-MM-JJ), en UTC comme toutes les dates de Keryx.
// Tout est construit ET formaté en UTC : un 1er du mois bâti en heure locale puis converti par toISOString()
// devenait le dernier jour du mois précédent à l'est de Greenwich (et l'inverse n'était juste que par chance à l'ouest).
export const isoDay = (d) => d.toISOString().slice(0, 10)

export const monthStartUtc = (now = new Date()) => isoDay(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)))
