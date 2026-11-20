// Libellés et cycle de vie (miroir de keryx/workflow.py — le serveur reste l'autorité).
export const STATUS = {
  nouveau: { label: 'Nouveau', color: '#1F5FD1', phase: 'Détection et signalement' },
  en_evaluation: { label: 'En évaluation', color: '#B7791F', phase: 'Évaluation et décision' },
  en_reponse: { label: 'En réponse', color: '#B4232C', phase: 'Confinement, éradication, rétablissement' },
  cloture: { label: 'Clôturé', color: '#2F855A', phase: 'Incident traité' },
  faux_positif: { label: 'Faux positif', color: '#8D97A5', phase: 'Clos après évaluation' },
  retour_experience: { label: "Retour d'exp.", color: '#5B3FC4', phase: 'Tirer les enseignements' },
}

export const TRANSITIONS = {
  nouveau: ['en_evaluation'],
  en_evaluation: ['faux_positif', 'en_reponse'],
  en_reponse: ['cloture'],
  cloture: ['retour_experience'],
  faux_positif: [],
  retour_experience: [],
}

export const KANBAN_COLUMNS = ['nouveau', 'en_evaluation', 'en_reponse', 'cloture', 'retour_experience']

export const VERDICTS = {
  vrai_positif_avere: 'Vrai positif — incident avéré',
  vrai_positif_non_avere: 'Vrai positif — non avéré',
  faux_positif: 'Faux positif',
}
export const DOMMAGES = { limites: 'Limités', significatifs: 'Significatifs', graves: 'Graves' }
export const IMPORTANCES = { standard: 'Standard', sensible: 'Sensible', vital: 'Vital' }
export const TLPS = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']
export const ROLES = { admin: 'Admin', manager: "Manager d'équipe", analyst: 'Analyste', client: 'Client' }
export const SCAN = { non_analyse: 'Non analysé', sain: 'Sain', quarantaine: 'Quarantaine' }
export const LIFECYCLE = { conserve: 'Conservé', restitue: 'Restitué', detruit: 'Détruit' }
export const MITRE_SOURCE = { wazuh: 'Wazuh', table: 'Table', manuel: 'Manuel', a_completer: 'à compléter' }

export function formatUtc(iso) {
  if (!iso) return '—'
  return iso.replace('T', ' ').slice(0, 16) + ' UTC'
}
