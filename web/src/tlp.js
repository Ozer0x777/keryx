// Marquage TLP 2.0, du moins au plus restrictif, et plancher d'un client (ADR-0033). Fonctions pures, testées.
import { TLPS } from './labels.js'

export const tlpRang = (x) => TLPS.indexOf(x)

// Vrai si `x` est sous le plancher (aucun plancher : jamais).
export const tlpSous = (x, plancher) => Boolean(plancher) && tlpRang(x) < tlpRang(plancher)

// Le plus restrictif des deux : niveau proposé pour une nouvelle pièce d'un ticket.
export const tlpAuMoins = (x, plancher) => (tlpSous(x, plancher) ? plancher : x)
