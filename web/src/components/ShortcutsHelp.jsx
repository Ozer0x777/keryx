import { useEffect, useRef } from 'react'
import { t as tr } from '../i18n.js'

// Aide des raccourcis clavier de la page (touche « ? »). `keys` : [[touche, ce qu'elle fait], …].
export default function ShortcutsHelp({ keys, onClose }) {
  const ref = useRef(null)
  useEffect(() => { const d = ref.current; d?.showModal?.(); return () => d?.close?.() }, [])
  return (
    <dialog ref={ref} className="dialog" aria-labelledby="raccourcis-titre" onCancel={(e) => { e.preventDefault(); onClose() }}>
      <h2 id="raccourcis-titre">{tr('Raccourcis clavier')}</h2>
      <dl className="kv shortcuts">
        {keys.map(([k, what]) => <div key={k} className="contents"><dt><kbd>{k}</kbd></dt><dd>{what}</dd></div>)}
      </dl>
      <p className="field-hint">{tr('Les raccourcis ne réagissent pas pendant une saisie.')}</p>
      <div className="row end"><button type="button" className="primary" onClick={onClose} autoFocus>{tr('Fermer')}</button></div>
    </dialog>
  )
}
