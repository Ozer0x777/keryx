import { t as tr } from './i18n.js'
import { STATUS } from './labels.js'

// Changements de statut qui demandent une confirmation (ADR-0024), communs à la fiche ticket et au Kanban :
// « Faux positif » (état final, motif interne obligatoire), puis les étapes qui engagent le client ou ferment le dossier.
export const CONFIRMED_STEPS = ['faux_positif', 'en_reponse', 'cloture', 'retour_experience']
export const needsConfirm = (target) => CONFIRMED_STEPS.includes(target)

// Ouvre le dialogue de confirmation ; `send(reason)` fait l'appel au serveur (le motif n'est fourni que pour un
// faux positif). Un refus du serveur s'affiche dans le dialogue, qui reste ouvert. Rend true si le statut a changé.
export async function confirmTransition(ask, { ref, client, target, send }) {
  if (target === 'faux_positif') {
    const r = await ask({
      title: tr('Clore {ref} comme faux positif ?', { ref }),
      body: <>
        <p>{tr("« Faux positif » est un état final : le ticket est clos, il ne pourra plus changer de statut ni être requalifié. Le verdict « Faux positif » doit avoir été enregistré dans la qualification.")}</p>
        <p>{tr("Le client {client} verra le changement de statut, mais pas le motif ci-dessous : il reste interne et figure au registre des actions.", { client })}</p>
      </>,
      fields: [{ name: 'reason', type: 'textarea', label: tr('Motif du faux positif (interne)'), minLength: 10, maxLength: 1000,
        hint: tr("Pourquoi l'alerte n'est pas un incident : ce qui a été vérifié et la conclusion.") }],
      confirm: tr('Clore comme faux positif'), danger: true,
      action: ({ reason }) => send(reason),
    })
    return !!r
  }
  const r = await ask({
    title: tr('Passer {ref} au statut « {s} » ?', { ref, s: STATUS[target].label }),
    body: <>
      <p>{tr('Le client {client} voit ce changement de statut dans son portail.', { client })}</p>
      {target === 'en_reponse' && <p>{tr("Le ticket passe en phase de réponse : confinement, éradication et rétablissement. Le verdict ne pourra plus changer.")}</p>}
      {target === 'cloture' && <p>{tr("Le ticket sort de la phase de réponse : seule l'étape du retour d'expérience peut suivre, et un incident Élevé ou Critique reste en attente de ce retour d'expérience tant qu'il n'est pas rédigé.")}</p>}
      {target === 'retour_experience' && <p>{tr("Le retour d'expérience est l'étape finale : le ticket sera figé.")}</p>}
    </>,
    confirm: tr('Passer au statut « {s} »', { s: STATUS[target].label }), danger: target !== 'en_reponse',
    action: () => send(),
  })
  return !!r
}
