import { useCallback, useState } from 'react'
import { utcClock } from '../dates.js'
import { t as tr } from '../i18n.js'

// Retour d'une action au plus près de son bouton : « Enregistré à 14:02 UTC » ou l'erreur (rouge, role=alert).
// La zone live de la page reste alimentée pour les lecteurs d'écran ; ce message-ci est celui que l'on voit.
export const savedAt = () => tr('Enregistré à {h}', { h: utcClock() })

//   const [status, track] = useActionStatus()
//   track(() => api(…))               → true (ou la valeur rendue) si réussi, false sinon ; l'état porte le message
//   <ActionStatus state={status} />   à côté du bouton
export function useActionStatus() {
  const [state, setState] = useState(null)   // null | { ok: texte } | { error: texte }
  const track = useCallback(async (fn, okText) => {
    setState(null)
    try {
      const r = await fn()
      setState({ ok: okText || savedAt() })
      return r ?? true
    } catch (e) {
      setState({ error: e.message })
      return false
    }
  }, [])
  return [state, track, setState]
}

// `live` : à poser quand aucune zone live de page n'annonce déjà le succès (sinon il serait lu deux fois).
export function ActionStatus({ state, live = false }) {
  if (!state) return null
  if (state.error) return <p className="error action-status" role="alert">{state.error}</p>
  return <span className="action-status ok" role={live ? 'status' : undefined}>{state.ok}</span>
}
