import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { t as tr } from '../i18n.js'

// Dialogue de confirmation et de saisie : remplace window.prompt / window.confirm.
// <dialog> natif ouvert par showModal() : le reste de la page est inerte (focus piégé par le navigateur), Échap ferme,
// le focus revient au déclencheur. Le titre nomme l'objet et la conséquence, le bouton d'action porte le verbe.
// Les champs sont validés en ligne (message sous le champ) ; l'action s'exécute dialogue ouvert, son échec s'affiche
// à côté du bouton au lieu de fermer la fenêtre.
//
//   const [ask, dialog] = useConfirm()
//   const r = await ask({ title, body, fields: [{ name: 'reason', label, minLength: 3 }], confirm: tr('Détruire'), danger: true,
//                         action: (values) => api(…) })
//   if (!r) return            // annulé ; sinon r = { values, result }
//   … et {dialog} dans le rendu du composant.
export function useConfirm() {
  const [req, setReq] = useState(null)
  const ask = useCallback((options) => new Promise((resolve) => setReq({ options, resolve, key: Date.now() })), [])
  const node = req
    ? <ConfirmDialog key={req.key} {...req.options} onDone={(out) => { setReq(null); req.resolve(out) }} />
    : null
  return [ask, node]
}

function check(field, value, values) {
  const v = field.type === 'password' ? value : value.trim()   // un mot de passe se compare tel que saisi
  const required = field.required !== false
  if (!v) return required ? tr('Ce champ est obligatoire.') : ''
  if (field.minLength && v.length < field.minLength) return tr('Saisir au moins {n} caractères.', { n: field.minLength })
  return field.validate ? (field.validate(v, values) || '') : ''
}

function ConfirmDialog({ title, body, fields = [], confirm, cancel, danger = false, action, onDone }) {
  const ref = useRef(null)
  const opener = useRef(null)
  const uid = useId()
  const [values, setValues] = useState(() => Object.fromEntries(fields.map((f) => [f.name, f.initial ?? ''])))
  const [errors, setErrors] = useState({})
  const [failure, setFailure] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const d = ref.current
    opener.current = document.activeElement
    if (!d.open) d.showModal()
    // Premier champ s'il y en a un ; sinon « Annuler » : une action grave ne part pas sur une frappe d'Entrée involontaire.
    const first = d.querySelector('input, textarea, select') || d.querySelector('[data-cancel]')
    first?.focus()
    if (first?.select && first.value) first.select()
    return () => { if (d.open) d.close() }
  }, [])

  const finish = (out) => {
    ref.current?.close()
    onDone(out)
    // Le navigateur rend le focus au déclencheur à la fermeture ; on l'assure s'il a été redessiné entre-temps.
    const o = opener.current
    if (o?.isConnected && document.activeElement !== o) o.focus?.()
  }

  const submit = async (e) => {
    e.preventDefault()
    if (busy) return
    const found = Object.fromEntries(fields.map((f) => [f.name, check(f, values[f.name], values)]).filter(([, m]) => m))
    setErrors(found)
    setFailure('')
    const bad = fields.find((f) => found[f.name])
    if (bad) { ref.current.querySelector(`[name="${bad.name}"]`)?.focus(); return }
    const clean = Object.fromEntries(fields.map((f) => [f.name, f.type === 'password' ? values[f.name] : values[f.name].trim()]))
    if (!action) { finish({ values: clean, result: undefined }); return }
    setBusy(true)
    try {
      const result = await action(clean)
      finish({ values: clean, result })
    } catch (err) {
      setBusy(false)
      setFailure(err.message || tr("L'action a échoué."))
    }
  }

  const change = (f, value) => {
    const next = { ...values, [f.name]: value }
    setValues(next)
    // Une erreur déjà affichée se corrige pendant la saisie (pas besoin de revalider pour la voir disparaître).
    if (Object.keys(errors).length) setErrors(Object.fromEntries(fields.filter((x) => errors[x.name]).map((x) => [x.name, check(x, next[x.name], next)]).filter(([, m]) => m)))
  }

  return (
    <dialog ref={ref} className="dialog" aria-labelledby={`${uid}-t`} aria-describedby={body ? `${uid}-b` : undefined}
      onCancel={(e) => { e.preventDefault(); if (!busy) finish(null) }}>
      <form onSubmit={submit} noValidate>
        <h2 id={`${uid}-t`}>{title}</h2>
        {body && <div className="dialog-body" id={`${uid}-b`}>{body}</div>}
        {fields.map((f) => {
          const id = `${uid}-${f.name}`
          const err = errors[f.name]
          const shared = {
            id, name: f.name, value: values[f.name], onChange: (e) => change(f, e.target.value), maxLength: f.maxLength,
            placeholder: f.placeholder, autoComplete: f.autoComplete || 'off', className: f.mono ? 'mono' : undefined,
            'aria-invalid': err ? 'true' : undefined, 'aria-required': f.required !== false ? 'true' : undefined,
            'aria-describedby': [err && `${id}-e`, f.hint && `${id}-h`].filter(Boolean).join(' ') || undefined,
          }
          return (
            <div className="field" key={f.name}>
              <label htmlFor={id}>{f.label}</label>
              {f.type === 'textarea' ? <textarea rows={3} {...shared} /> : <input type={f.type || 'text'} {...shared} />}
              {f.hint && <p className="field-hint" id={`${id}-h`}>{f.hint}</p>}
              {err && <p className="field-error" id={`${id}-e`}>{err}</p>}
            </div>
          )
        })}
        {failure && <p className="error" role="alert">{failure}</p>}
        <div className="dialog-actions">
          <button type="button" data-cancel onClick={() => finish(null)} disabled={busy}>{cancel || tr('Annuler')}</button>
          <button type="submit" className={danger ? 'danger-solid' : 'primary'} disabled={busy} aria-busy={busy || undefined}>{confirm}</button>
        </div>
      </form>
    </dialog>
  )
}
