import { t as tr } from '../../i18n.js'
import { useEffect, useState } from 'react'
import { api, downloadBlob } from '../../api.js'
import { formatUtc, ROLES } from '../../labels.js'
import { useLocalList } from '../../components/LocalList.jsx'

const texteRevue = (u) => [u.username, u.display_name, u.role, ...u.clients].join(' ')

export default function Review() {
  const [review, setReview] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/admin/revue-comptes').then(setReview).catch((e) => setError(e.message)) }, [])
  const list = useLocalList(review?.items, texteRevue, tr('Pages de la revue des comptes'))
  const exportReview = () => downloadBlob(new Blob([JSON.stringify(review, null, 2)], { type: 'application/json' }),
    `revue-comptes-${review.generated_at.slice(0, 10)}.json`)
  return (
    <>
      {error && <p className="error" role="alert">{error}</p>}
      <section className="card section" aria-label={tr("Revue des comptes")}>
        <header className="section-head">
          <h2>{tr("Revue des comptes et des droits")}</h2>
          {review && <button type="button" onClick={exportReview}>{tr("Exporter (JSON)")}</button>}
        </header>
        <div className="section-body">
          <p className="muted small">{tr('À réaliser au moins chaque mois (PDIS IV.3.4.b). Généré le {when}.', { when: review ? formatUtc(review.generated_at) : '…' })}</p>
          {list.search}
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th scope="col">{tr("Identifiant")}</th><th scope="col">{tr("Nom")}</th><th scope="col">{tr("Rôle")}</th><th scope="col">{tr("Clients")}</th><th scope="col">{tr("Dernière connexion")}</th><th scope="col">{tr("Codes de secours")}</th><th scope="col">{tr("État")}</th></tr></thead>
              <tbody>
                {list.rows?.map((u) => (
                  <tr key={u.username}>
                    <td className="mono">{u.username}</td><td>{u.display_name}</td><td>{ROLES[u.role]}</td>
                    <td className="mono small">{u.clients.join(', ') || '—'}</td>
                    <td className="mono small">{formatUtc(u.last_login_at)}</td>
                    <td className="num">{u.recovery_codes_left}</td>
                    <td>{!u.active ? tr('Désactivé') : u.locked ? <span className="pill danger">{tr("Verrouillé")}</span> : tr('Actif')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {list.pager}
        </div>
      </section>
    </>
  )
}
