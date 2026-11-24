import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useBlocker } from 'react-router-dom'
import { t as tr } from '../i18n.js'

// Saisies non enregistrées de la fiche ticket (ADR-0024).
// Chaque zone de saisie déclare son état par useUnsaved(id, libellé, modifié) ; la fiche en déduit l'indicateur de
// l'en-tête et le garde-fou de sortie : changement de page dans l'application (useBlocker, routeur à données) et
// fermeture ou rechargement de l'onglet (beforeunload). Rien n'est enregistré automatiquement : une saisie qui
// écrit au registre des actions ou à l'audit ne part que sur un clic explicite.
const UnsavedContext = createContext(() => {})

// État partagé avec la déconnexion (App.jsx) : savoir s'il reste des saisies, et couper le garde-fou une fois la sortie
// confirmée (sinon la redirection vers le fournisseur d'identité déclencherait « Quitter le site ? » après coup).
let pending = []
let off = false
export const unsavedLabels = () => (off ? [] : pending)
export function disableLeaveGuard() { off = true }

export function useUnsavedRegistry() {
  const [dirty, setDirty] = useState({})   // { id: libellé }
  const report = useCallback((id, label) => {
    setDirty((prev) => {
      if ((prev[id] || null) === (label || null)) return prev
      const next = { ...prev }
      if (label) next[id] = label; else delete next[id]
      return next
    })
  }, [])
  const labels = useMemo(() => Object.values(dirty), [dirty])
  const ids = useMemo(() => Object.keys(dirty), [dirty])
  return { report, labels, ids }
}

export const UnsavedProvider = UnsavedContext.Provider

// `label` : nom de la zone, affiché dans l'indicateur ; `dirty` : la saisie diffère de ce qui est enregistré.
export function useUnsaved(id, label, dirty) {
  const report = useContext(UnsavedContext)
  useEffect(() => {
    report(id, dirty ? label : null)
    return () => report(id, null)
  }, [report, id, label, dirty])
}

// Pastille d'une zone : texte, pas seulement une couleur.
export function UnsavedBadge({ show }) {
  return show ? <span className="pill warn unsaved-badge">{tr('Modifications non enregistrées')}</span> : null
}

// Garde-fou de sortie. `ask` vient de useConfirm : la question nomme les zones concernées.
export function useLeaveGuard(labels, ask) {
  const active = labels.length > 0
  useEffect(() => { off = false }, [])                       // nouvelle fiche, nouvelle session : garde-fou réarmé
  useEffect(() => { pending = labels; return () => { pending = [] } }, [labels])
  const blocker = useBlocker(({ currentLocation, nextLocation }) => !off && active && currentLocation.pathname !== nextLocation.pathname)
  const latest = useRef({})
  latest.current = { blocker, labels, ask }
  useEffect(() => {
    if (blocker.state !== 'blocked') return
    // Une seule question par blocage : l'effet ne dépend que de l'état du blocage, le reste est lu au moment voulu.
    const { labels: zones, ask: question } = latest.current
    question({
      title: tr('Quitter la page sans enregistrer ?'),
      body: <>
        <p>{tr("Saisies non enregistrées dans le ticket : {zones}.", { zones: zones.join(', ') })}</p>
        <p>{zones.includes(tr('commentaire'))
          ? tr("Un commentaire non publié reste en brouillon dans cet onglet ; le reste sera perdu si vous quittez cette page.")
          : tr("Elles seront perdues si vous quittez cette page.")}</p>
      </>,
      confirm: tr('Quitter sans enregistrer'), cancel: tr('Rester sur la page'), danger: true,
    }).then((r) => {
      const b = latest.current.blocker
      if (b.state !== 'blocked') return
      if (r) b.proceed(); else b.reset()
    })
  }, [blocker.state])
  useEffect(() => {
    if (!active) return undefined
    const handler = (e) => { if (off) return; e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [active])
}

// Zone de l'en-tête : liste des saisies en cours, annoncée aux lecteurs d'écran.
export function UnsavedSummary({ labels }) {
  // Zone live toujours présente : seul son texte change (une zone ajoutée déjà remplie n'est pas toujours annoncée).
  return (
    <p className={`unsaved-summary${labels.length ? ' pill warn' : ''}`} role="status">
      {labels.length ? tr('Non enregistré : {zones}', { zones: labels.join(', ') }) : ''}
    </p>
  )
}

// Brouillon de commentaire (ADR-0024) : sessionStorage, propre à l'onglet, jamais envoyé au serveur ; effacé à la
// publication. Le stockage peut être indisponible (navigation privée, blocage) : la page marche sans.
export const draftKey = (user, ref) => `keryx:brouillon:${user}:${ref}`
export function readDraft(key) { try { return sessionStorage.getItem(key) || '' } catch { return '' } }
export function writeDraft(key, html) {
  try { if (html) sessionStorage.setItem(key, html); else sessionStorage.removeItem(key) } catch { /* stockage indisponible */ }
}
// `keepUser` : garde les brouillons de ce compte (connexion du même compte après expiration de la session).
export function clearDrafts(keepUser) {
  try {
    const keep = keepUser ? `keryx:brouillon:${keepUser}:` : null
    for (const k of Object.keys(sessionStorage)) {
      if (k.startsWith('keryx:brouillon:') && !(keep && k.startsWith(keep))) sessionStorage.removeItem(k)
    }
  } catch { /* stockage indisponible */ }
}
