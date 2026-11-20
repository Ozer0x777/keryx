import { t as tr } from '../../i18n.js'
import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import AuditViewer from '../../components/AuditViewer.jsx'

export default function Audit() {
  const [chain, setChain] = useState(null)
  const [error, setError] = useState('')
  const [cp, setCp] = useState(null)
  const [stamps, setStamps] = useState({ enabled: false, items: [] })
  const [stampMsg, setStampMsg] = useState('')
  const loadStamps = () => api('/audit/timestamps').then(setStamps).catch(() => {})
  useEffect(() => { loadStamps() }, [])
  const stampCheckpoint = async () => { setStampMsg(''); try { const r = await api('/audit/checkpoint/timestamp', { method: 'POST' }); setStampMsg(`Point de contrôle ${r.seq} horodaté (série ${r.serial}).`); loadStamps() } catch (e) { setError(e.message) } }
  const verifyStamp = async (id) => { try { const r = await api(`/timestamps/${id}/verify`, { method: 'POST' }); setStampMsg(r.valid ? 'Jeton valide.' : `Jeton NON valide : ${r.error}`) } catch (e) { setError(e.message) } }
  const verify = async () => {
    setChain(null)
    try { setChain(await api('/audit/verify')) } catch (e) { setError(e.message) }
  }
  const checkpoint = async () => { try { setCp(await api('/audit/checkpoint')) } catch (e) { setError(e.message) } }
  return (
    <>
      {error && <p className="error" role="alert">{error}</p>}
      <section className="card section" aria-label={tr("Journal d'audit")}>
        <header className="section-head"><h2>{tr("Intégrité du journal d'audit")}</h2><button type="button" className="primary" onClick={verify}>{tr("Vérifier la chaîne")}</button></header>
        <div className="section-body">
          {chain && (chain.chain_ok
            ? <p className="banner ok">Chaîne intègre : {chain.entries} entrées vérifiées (scellement HMAC).</p>
            : <p className="banner danger">Chaîne ROMPUE à l'entrée {chain.first_broken_seq}. Prévenir le RSSI.</p>)}
          <p className="muted small">Pour détecter une suppression des dernières entrées, comparer avec un point de contrôle archivé hors de Keryx (<span className="mono">{tr("keryx checkpoint")}</span>) ou avec le flux syslog envoyé à Wazuh.</p>
        </div>
      </section>
      <section className="card section" aria-label={tr("Point de contrôle")}>
        <header className="section-head"><h2>{tr("Point de contrôle")}</h2><button type="button" onClick={checkpoint}>{tr("Générer")}</button></header>
        <p className="muted small">À archiver hors de Keryx (coffre, ticket de changement) : il permet de détecter la suppression des dernières entrées.</p>
        {cp && <p className="mono small" style={{ wordBreak: 'break-all' }}>{cp.value}</p>}
        {stamps.enabled && (
          <>
            <h3>Horodatage de confiance (RFC 3161)</h3>
            <p className="muted small">{tr("Fait attester par une autorité d'horodatage l'état du journal à cet instant : seule l'empreinte du point de contrôle quitte Keryx.")}</p>
            <button type="button" onClick={stampCheckpoint}>{tr("Horodater le point de contrôle actuel")}</button>
            <p className="live" role="status">{stampMsg}</p>
            <ul className="found">{stamps.items.map((t) => <li key={t.id} className="small"><span className="mono">n° {t.seq}</span> · {t.gen_time} · <button type="button" className="link" onClick={() => verifyStamp(t.id)}>{tr("Vérifier")}</button></li>)}</ul>
          </>
        )}
      </section>
      <AuditViewer />
    </>
  )
}
