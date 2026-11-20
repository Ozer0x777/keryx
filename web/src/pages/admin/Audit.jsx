import { useState } from 'react'
import { api } from '../../api.js'

export default function Audit() {
  const [chain, setChain] = useState(null)
  const [error, setError] = useState('')
  const verify = async () => {
    setChain(null)
    try { setChain(await api('/audit/verify')) } catch (e) { setError(e.message) }
  }
  return (
    <>
      {error && <p className="error" role="alert">{error}</p>}
      <section className="card section" aria-label="Journal d'audit">
        <header className="section-head"><h2>Intégrité du journal d'audit</h2><button type="button" className="primary" onClick={verify}>Vérifier la chaîne</button></header>
        <div className="section-body">
          {chain && (chain.chain_ok
            ? <p className="banner ok">Chaîne intègre : {chain.entries} entrées vérifiées (scellement HMAC).</p>
            : <p className="banner danger">Chaîne ROMPUE à l'entrée {chain.first_broken_seq}. Prévenir le RSSI.</p>)}
          <p className="muted small">Pour détecter une suppression des dernières entrées, comparer avec un point de contrôle archivé hors de Keryx (<span className="mono">keryx checkpoint</span>) ou avec le flux syslog envoyé à Wazuh.</p>
        </div>
      </section>
    </>
  )
}
