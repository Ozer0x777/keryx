import { useState } from 'react'

// Secret affiché une seule fois (mot de passe temporaire, clé d'API, URI TOTP, codes de secours).
export default function OneTime({ title, items, onClose }) {
  const [copied, setCopied] = useState('')
  const copy = async (label, value) => {
    try { await navigator.clipboard.writeText(value); setCopied(label) } catch { setCopied('') }
  }
  return (
    <div className="banner warn" role="alert">
      <strong>{title}</strong> — à noter maintenant : ces valeurs ne seront plus affichées.
      <dl className="onetime">
        {items.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd><code className="mono">{Array.isArray(value) ? value.join('  ') : value}</code>{' '}
              <button type="button" className="small-btn" onClick={() => copy(label, Array.isArray(value) ? value.join('\n') : value)}>
                {copied === label ? 'Copié' : 'Copier'}
              </button></dd>
          </div>
        ))}
      </dl>
      <button type="button" onClick={onClose}>J'ai noté ces valeurs</button>
    </div>
  )
}
