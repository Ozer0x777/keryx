import { useEffect, useState } from 'react'
import { api, downloadBlob } from '../../api.js'
import { formatUtc, ROLES } from '../../labels.js'

export default function Review() {
  const [review, setReview] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/admin/revue-comptes').then(setReview).catch((e) => setError(e.message)) }, [])
  const exportReview = () => downloadBlob(new Blob([JSON.stringify(review, null, 2)], { type: 'application/json' }),
    `revue-comptes-${review.generated_at.slice(0, 10)}.json`)
  return (
    <>
      {error && <p className="error" role="alert">{error}</p>}
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
