import { createContext, useContext, useEffect, useRef, useState } from 'react'

// Panneaux repliables de la fiche ticket (<details> natif). Chaque panneau a un identifiant ; ceux qui sont ouverts
// d'entrée dépendent de la phase du ticket (au statut Nouveau : l'alerte, la qualification et l'affectation ; le reste
// est replié). L'utilisateur plie et déplie ensuite à sa guise : son choix tient tant que le statut ne change pas.
// Un panneau replié garde son contenu monté : une saisie en cours n'est pas perdue.
export const OPEN_BY_STATUS = {
  nouveau: ['description', 'alerte', 'qualification', 'affectation'],
  en_evaluation: ['description', 'alerte', 'preuves', 'suivi-client', 'commentaires', 'qualification', 'mitre', 'affectation'],
  en_reponse: ['description', 'preuves', 'actions', 'suivi-client', 'commentaires', 'qualification', 'mitre', 'isi', 'affectation', 'liens'],
  cloture: ['synthese', 'commentaires', 'isi', 'details'],
  faux_positif: ['description', 'commentaires', 'qualification', 'details'],
  retour_experience: ['synthese', 'actions', 'commentaires', 'details'],
}
// Portail client : peu de panneaux, l'essentiel est ouvert.
export const OPEN_FOR_CLIENT = ['description', 'suivi-client', 'preuves', 'commentaires']

export const PhaseContext = createContext({ status: '', open: null })

// `summary` : ce qu'il faut savoir du panneau sans l'ouvrir (compteur, verdict, assigné…), affiché après le titre.
// `tools` : boutons du panneau ; ils sont dans le corps, pas dans <summary> (un bouton dans un bouton de pliage ne
// serait ni cliquable proprement ni annoncé correctement).
// `onToggle(ouvert)` : prévient le panneau qu'il vient d'être déplié ou replié (chargement à la première ouverture).
export default function Section({ id, title, summary, tools, children, className = '', onToggle }) {
  const { status, open: openIds } = useContext(PhaseContext)
  const byDefault = openIds ? openIds.includes(id) : true
  const [open, setOpen] = useState(byDefault)
  const phase = useRef(status)
  useEffect(() => {
    if (phase.current !== status) { phase.current = status; setOpen(byDefault) }
  }, [status, byDefault])
  return (
    <section className={`card section fold ${className}`.trim()} aria-label={title}>
      <details open={open} onToggle={(e) => { setOpen(e.currentTarget.open); onToggle?.(e.currentTarget.open) }}>
        <summary><h2>{title}</h2>{summary && <span className="fold-summary">{summary}</span>}</summary>
        <div className="section-body">
          {tools && <div className="section-tools">{tools}</div>}
          {children}
        </div>
      </details>
    </section>
  )
}
