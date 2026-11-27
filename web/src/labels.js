import { t } from './i18n.js'

// Libellés et cycle de vie (miroir de keryx/workflow.py — le serveur reste l'autorité).
export const STATUS = {
  nouveau: { get label() { return t('Nouveau') }, color: '#1F5FD1', get phase() { return t('Détection et signalement') } },
  en_evaluation: { get label() { return t('En évaluation') }, color: '#B7791F', get phase() { return t('Évaluation et décision') } },
  en_reponse: { get label() { return t('En réponse') }, color: '#B4232C', get phase() { return t('Confinement, éradication, rétablissement') } },
  cloture: { get label() { return t('Clôturé') }, color: '#2F855A', get phase() { return t('Incident traité') } },
  faux_positif: { get label() { return t('Faux positif') }, color: '#8D97A5', get phase() { return t('Clos après évaluation') } },
  retour_experience: { get label() { return t("Retour d'exp.") }, color: '#5B3FC4', get phase() { return t('Tirer les enseignements') } },
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
  get vrai_positif_avere() { return t('Vrai positif — incident avéré') },
  get vrai_positif_non_avere() { return t('Vrai positif — non avéré') },
  get faux_positif() { return t('Faux positif') },
}
export const DOMMAGES = { get limites() { return t('Limités') }, get significatifs() { return t('Significatifs') }, get graves() { return t('Graves') } }
export const IMPORTANCES = { get standard() { return t('Standard') }, get sensible() { return t('Sensible') }, get vital() { return t('Vital') } }
export const TLPS = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']
export const ROLES = { get admin() { return t('Admin') }, get manager() { return t("Manager d'équipe") }, get analyst() { return t('Analyste') }, get client() { return t('Client') } }
export const SCAN = { get non_analyse() { return t('Non analysé') }, get sain() { return t('Sain') }, get quarantaine() { return t('Quarantaine') }, get non_analysable() { return t('Non analysable') } }
// Pièce isolée : en quarantaine, ou que l'antivirus ne peut pas analyser (archive chiffrée, endommagée), PDIS IV.3.13.a.
export const isole = (status) => status === 'quarantaine' || status === 'non_analysable'
export const LIFECYCLE = { get conserve() { return t('Conservé') }, get restitue() { return t('Restitué') }, get detruit() { return t('Détruit') } }
export const MITRE_SOURCE = { get wazuh() { return t('Wazuh') }, get table() { return t('Table') }, get manuel() { return t('Manuel') }, get a_completer() { return t('à compléter') } }

export function formatUtc(iso) {
  if (!iso) return '—'
  return iso.replace('T', ' ').slice(0, 16) + ' UTC'
}
