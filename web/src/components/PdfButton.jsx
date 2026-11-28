import { useState } from 'react'
import { api, downloadBlob } from '../api.js'
import { t as tr } from '../i18n.js'

// PDF produit par le serveur (ADR-0036) : mêmes droits et même contenu que la page, mise en page fixe, sans dépendre
// de l'impression du navigateur. Le bouton « Imprimer » reste à côté.
export default function PdfButton({ path, params, filename, primary = false, disabled = false }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const go = async () => {
    setBusy(true); setError('')
    try { downloadBlob(await api(path, { params }), filename) } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return (
    <>
      <button type="button" className={primary ? 'primary' : ''} onClick={go} disabled={disabled || busy} aria-busy={busy}>
        {busy ? tr('Préparation du PDF…') : tr('Télécharger le PDF')}
      </button>
      {error && <span className="error small" role="alert">{error}</span>}
    </>
  )
}
