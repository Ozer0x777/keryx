import { useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import { t as tr } from '../i18n.js'
import { STATUS } from '../labels.js'
import { Severity } from './Badges.jsx'

// Fenêtre « Lier à un autre ticket » : type de lien expliqué, sens du lien parent, recherche (référence, champ précis
// ou texte libre) qui dit où la valeur a été trouvée, conséquence écrite avant de valider. Tickets du même client
// seulement : le serveur ne cherche jamais ailleurs.
export const KINDS = {
  lie: { label: () => tr('Lié'), help: () => tr('Même attaque ou incidents connexes ; chacun garde son suivi.') },
  parent: { label: () => tr('Parent / enfant'), help: () => tr("Un ticket regroupe les autres (campagne, plusieurs machines) ; on travaille sur le parent.") },
  doublon: { label: () => tr('Doublon'), help: () => tr('La même alerte en double. Proposé ensuite : fusionner et clore le doublon.') },
}
const OU = { alerte: () => tr('alerte brute'), description: () => tr('description'), titre: () => tr('titre'), 'règle': () => tr('règle'),
  agent: () => tr('agent'), commentaire: () => tr('commentaire'), ref: () => tr('référence'), regle: () => tr('règle') }

export default function LinkDialog({ t, enc, initialQuery = '', onClose, onLinked, onMerge }) {
  const ref = useRef(null)
  const [kind, setKind] = useState('lie')
  const [sens, setSens] = useState('enfant_de')
  const [q, setQ] = useState(initialQuery)
  const [res, setRes] = useState(null)
  const [pick, setPick] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { const d = ref.current; d?.showModal?.(); return () => d?.close?.() }, [])
  // Recherche après une courte pause de frappe ; une réponse dépassée par une plus récente est ignorée.
  useEffect(() => {
    const v = q.trim()
    if (!v) { setRes(null); return undefined }
    let alive = true
    const id = setTimeout(() => {
      api(`/tickets/${enc}/links/search`, { params: { q: v } }).then((r) => { if (alive) { setRes(r.items); setErr('') } }).catch((e) => alive && setErr(e.message))
    }, 250)
    return () => { alive = false; clearTimeout(id) }
  }, [q, enc])
  const chosen = res?.find((x) => x.ref === pick)
  const effect = !chosen ? null
    : kind === 'lie' ? tr('{a} et {b} sont liés ; chacun garde son statut. Le lien apparaît sur les deux fiches et au registre des actions.', { a: t.ref, b: chosen.ref })
      : kind === 'parent' ? (sens === 'enfant_de'
        ? tr('{a} devient un enfant de {b}. Les deux tickets gardent leur statut ; le lien apparaît sur les deux fiches et au registre des actions.', { a: t.ref, b: chosen.ref })
        : tr('{a} devient le parent de {b}. Les deux tickets gardent leur statut ; le lien apparaît sur les deux fiches et au registre des actions.', { a: t.ref, b: chosen.ref }))
        : tr('{a} est marqué doublon de {b}, sans autre changement. Pour rattacher ses alertes et ses commentaires à {b} et le clore, choisir « Fusionner ».', { a: t.ref, b: chosen.ref })
  const action = !chosen ? tr('Lier') : kind === 'parent'
    ? (sens === 'enfant_de' ? tr('Lier comme enfant de {b}', { b: chosen.ref }) : tr('Lier comme parent de {b}', { b: chosen.ref }))
    : kind === 'doublon' ? tr('Marquer doublon de {b}', { b: chosen.ref }) : tr('Lier à {b}', { b: chosen.ref })
  const submit = async (e) => {
    e.preventDefault()
    if (!chosen) return
    setBusy(true); setErr('')
    try {
      const r = await api(`/tickets/${enc}/links`, { method: 'POST', json: { ref: chosen.ref, kind, ...(kind === 'parent' ? { sens } : {}) } })
      onLinked(r.items); onClose()
    } catch (x) { setErr(x.message) } finally { setBusy(false) }
  }
  return (
    <dialog ref={ref} className="dialog link-dialog" aria-labelledby="link-dialog-title" onCancel={(e) => { e.preventDefault(); onClose() }}>
      <form method="dialog" onSubmit={submit} className="stack">
        <h2 id="link-dialog-title">{tr('Lier {ref} à un autre ticket', { ref: t.ref })}</h2>
        <fieldset className="link-kinds">
          <legend>{tr('Type de lien')}</legend>
          {Object.entries(KINDS).map(([k, v]) => (
            <label key={k} className={`link-kind${kind === k ? ' on' : ''}`}>
              <input type="radio" name="kind" value={k} checked={kind === k} onChange={() => setKind(k)} />
              <strong>{v.label()}</strong><span className="muted small">{v.help()}</span>
            </label>
          ))}
        </fieldset>
        {kind === 'parent' && (
          <fieldset className="link-sens">
            <legend className="sr-only">{tr('Sens du lien')}</legend>
            <label className="check"><input type="radio" name="sens" checked={sens === 'enfant_de'} onChange={() => setSens('enfant_de')} /> {tr('{a} est un enfant de…', { a: t.ref })}</label>
            <label className="check"><input type="radio" name="sens" checked={sens === 'parent_de'} onChange={() => setSens('parent_de')} /> {tr('{a} est le parent de…', { a: t.ref })}</label>
          </fieldset>
        )}
        <label>{tr('Rechercher le ticket')}
          <input type="search" value={q} autoFocus onChange={(e) => { setQ(e.target.value); setPick(null) }}
            placeholder={tr('ex. ACME-12, ip:185.220.101.4, compte:admin, ou un mot')} aria-describedby="link-search-help" />
        </label>
        <p className="field-hint" id="link-search-help">{tr('Par référence, par champ (ip:, hote:, agent:, regle:, compte:, hash:, domaine:) ou en texte libre (titre, description, alerte brute, commentaires). Tickets de ce client seulement.')}</p>
        {err && <p className="error" role="alert">{err}</p>}
        {res && res.length === 0 && <p className="muted">{tr('Aucun ticket de ce client ne correspond.')}</p>}
        {res && res.length > 0 && (
          <ul className="link-results" aria-label={tr('Résultats')}>
            {res.map((x) => (
              <li key={x.ref} className={pick === x.ref ? 'on' : ''}>
                <label>
                  <input type="radio" name="pick" value={x.ref} checked={pick === x.ref} disabled={x.deja_lie} onChange={() => setPick(x.ref)} />
                  <span className="mono">{x.ref}</span>
                  <span className="lr-title">{x.title}</span>
                  <span className="lr-tags"><Severity value={x.gravite || x.criticite_initiale} /> <span className="muted small">{STATUS[x.status]?.label || x.status}</span>{x.deja_lie && <span className="pill">{tr('déjà lié')}</span>}</span>
                  {x.trouve.length > 0 && (
                    <span className="lr-why muted small">{tr('trouvé dans : ')}{x.trouve.map((w, i) => (
                      <span key={i}>{i > 0 && ' · '}{(OU[w.ou] || (() => w.ou))()}{w.champ && w.champ !== w.ou ? <> <code>{w.champ}</code></> : ''}{w.extrait && <> « <mark>{w.extrait}</mark> »</>}</span>
                    ))}</span>
                  )}
                </label>
              </li>
            ))}
          </ul>
        )}
        {effect && <p className="link-effect">{effect}</p>}
        <div className="row gap end wrap">
          <button type="button" onClick={onClose}>{tr('Annuler')}</button>
          {kind === 'doublon' && chosen && onMerge && (
            <button type="button" className="danger" onClick={() => { onClose(); onMerge(chosen.ref) }}>{tr('Fusionner dans {b}…', { b: chosen.ref })}</button>
          )}
          <button type="submit" className="primary" disabled={!chosen || busy}>{action}</button>
        </div>
      </form>
    </dialog>
  )
}
