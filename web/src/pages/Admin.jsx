import { useEffect, useState } from 'react'
import { api, downloadBlob } from '../api.js'
import { useAuth } from '../App.jsx'
import { formatUtc, ROLES } from '../labels.js'

export default function Admin() {
  const { me } = useAuth()
  const [review, setReview] = useState(null)
  const [chain, setChain] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (me.role !== 'admin') return
    api('/admin/revue-comptes').then(setReview).catch((e) => setError(e.message))
  }, [me.role])

  if (me.role !== 'admin') return <p className="error">Réservé au rôle Admin.</p>
  const verify = async () => {
    setChain(null)
    try { setChain(await api('/audit/verify')) } catch (e) { setError(e.message) }
  }
  const exportReview = () => downloadBlob(new Blob([JSON.stringify(review, null, 2)], { type: 'application/json' }),
    `revue-comptes-${review.generated_at.slice(0, 10)}.json`)

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Administration</h1>
          <p className="muted">Le rôle Admin n'a pas accès au contenu des tickets (séparation administrateur / opérateur, PDIS IV.3.9).</p>
        </div>
      </header>
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
      <section className="card section" aria-label="Revue des comptes">
        <header className="section-head">
          <h2>Revue des comptes et des droits</h2>
          {review && <button type="button" onClick={exportReview}>Exporter (JSON)</button>}
        </header>
        <div className="section-body">
          <p className="muted small">À réaliser au moins chaque mois (PDIS IV.3.4.b). Généré le {review ? formatUtc(review.generated_at) : '…'}.</p>
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th scope="col">Identifiant</th><th scope="col">Nom</th><th scope="col">Rôle</th><th scope="col">Clients</th><th scope="col">Dernière connexion</th><th scope="col">Codes de secours</th><th scope="col">État</th></tr></thead>
              <tbody>
                {review?.items.map((u) => (
                  <tr key={u.username}>
                    <td className="mono">{u.username}</td><td>{u.display_name}</td><td>{ROLES[u.role]}</td>
                    <td className="mono small">{u.clients.join(', ') || '—'}</td>
                    <td className="mono small">{formatUtc(u.last_login_at)}</td>
                    <td className="num">{u.recovery_codes_left}</td>
                    <td>{!u.active ? 'Désactivé' : u.locked ? <span className="pill danger">Verrouillé</span> : 'Actif'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </>
  )
}
