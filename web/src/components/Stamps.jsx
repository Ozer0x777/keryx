import { t as tr } from '../i18n.js'
import { useCallback, useEffect, useState } from 'react'
import { api, downloadBlob } from '../api.js'
import { formatUtc } from '../labels.js'

// Horodatage de confiance RFC 3161 d'une pièce : liste des jetons, vérification, téléchargement, nouvelle demande.
export default function Stamps({ attachmentId, canStamp }) {
  const [data, setData] = useState(null)
  const [msg, setMsgText] = useState('')
  const [bad, setBad] = useState(false)  // message d'échec : l'état ne se déduit pas du texte (il est traduit)
  const setMsg = (text, isBad = false) => { setMsgText(text); setBad(isBad) }
  const load = useCallback(() => api(`/attachments/${attachmentId}/timestamps`).then(setData).catch(() => setData({ enabled: false, items: [] })), [attachmentId])
  useEffect(() => { load() }, [load])
  if (!data || (!data.enabled && data.items.length === 0)) return null
  const stamp = async () => { setMsg(''); try { await api(`/attachments/${attachmentId}/timestamp`, { method: 'POST' }); load() } catch (e) { setMsg(e.message, true) } }
  const verify = async (id) => {
    try {
      const r = await api(`/timestamps/${id}/verify`, { method: 'POST' })
      if (r.valid) setMsg(tr('Jeton valide : heure attestée {when}.', { when: formatUtc(r.gen_time) }))
      else setMsg(tr('Jeton NON valide : {err}', { err: r.error }), true)
    } catch (e) { setMsg(e.message, true) }
  }
  const token = async (t) => { try { downloadBlob(await api(`/timestamps/${t.id}/token`), `keryx-${t.serial}.tsr`) } catch (e) { setMsg(e.message, true) } }
  return (
    <div className="stamps small">
      {data.items.map((t) => (
        <div key={t.id}><span className="pill ok">{tr("Horodaté")}</span> {formatUtc(t.gen_time)} <button type="button" className="link" onClick={() => verify(t.id)}>{tr("Vérifier")}</button> · <button type="button" className="link" onClick={() => token(t)}>{tr("Jeton .tsr")}</button></div>
      ))}
      {canStamp && data.enabled && <button type="button" className="small-btn" onClick={stamp}>{data.items.length ? tr('Horodater de nouveau') : tr('Horodater (RFC 3161)')}</button>}
      {msg && <div role="status" className={bad ? 'error' : 'muted'}>{msg}</div>}
    </div>
  )
}
