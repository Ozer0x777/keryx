import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api.js'
import { ActionStatus, useActionStatus } from '../../components/ActionStatus.jsx'
import { t as tr } from '../../i18n.js'
import { formatUtc } from '../../labels.js'

// Canaux d'astreinte (ADR-0032), déclarés par l'Admin : une adresse appelée par le serveur est un réglage de sécurité.
// Le manager choisit ensuite, par client, le canal d'astreinte et le canal d'escalade parmi eux. L'adresse complète
// et le secret ne sont jamais réaffichés.
export const KINDS = {
  webhook_json: tr('Webhook JSON générique'),
  webhook_mattermost: tr('Webhook Mattermost / Slack'),
  webhook_teams: tr('Webhook Microsoft Teams (Workflows)'),
  email: tr("Courriel de l'équipe"),
}

function Canal({ c, reload }) {
  const [status, track, setStatus] = useActionStatus()
  const essai = async () => {
    const r = await track(() => api(`/admin/canaux/${c.id}/essai`, { method: 'POST' }))
    if (!r) return
    setStatus(r.statut === 'envoye'
      ? { ok: r.code ? tr('Message d’essai envoyé (réponse {code}).', { code: r.code }) : tr('Message d’essai envoyé.') }
      : { error: tr('Échec de l’essai ({e}{code}).', { e: r.erreur, code: r.code ? `, ${r.code}` : '' }) })
  }
  const basculer = () => track(async () => { await api(`/admin/canaux/${c.id}`, { method: 'PUT', json: { active: !c.active } }); reload() })
  return (
    <tr>
      <th scope="row">{c.name}{!c.active && <> <span className="pill">{tr('désactivé')}</span></>}</th>
      <td>{KINDS[c.kind] || c.kind}</td>
      <td className="mono small">{c.target}</td>
      <td>{[c.signed && tr('signé'), c.include_title && tr('avec le titre')].filter(Boolean).join(', ') || '—'}</td>
      <td className="small">{formatUtc(c.created_at)}</td>
      <td>
        <div className="row wrap gap">
          <button type="button" onClick={essai} disabled={!c.active}>{tr('Envoyer un essai')}</button>
          <button type="button" onClick={basculer}>{c.active ? tr('Désactiver') : tr('Réactiver')}</button>
        </div>
        <ActionStatus state={status} />
      </td>
    </tr>
  )
}

export default function Canaux() {
  const [items, setItems] = useState(null)
  const [error, setError] = useState('')
  const [kind, setKind] = useState('webhook_mattermost')
  const [status, track] = useActionStatus()
  const load = useCallback(() => api('/admin/canaux').then((r) => setItems(r.items)).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])
  const create = async (e) => {
    e.preventDefault()
    const form = e.currentTarget
    const f = new FormData(form)
    const json = { name: f.get('name'), kind, target: f.get('target'), include_title: f.get('include_title') === 'on' }
    if (kind === 'webhook_json' && f.get('secret')) json.secret = f.get('secret')
    const ok = await track(() => api('/admin/canaux', { method: 'POST', json }), tr('Canal ajouté.'))
    if (ok) { form.reset(); load() }
  }
  return (
    <>
      <section className="card section" aria-label={tr("Canaux d'astreinte")}>
        <h2>{tr("Canaux d'astreinte")}</h2>
        <p className="muted small">{tr("Où Keryx prévient l'équipe quand un ticket critique s'ouvre, puis l'escalade sans prise en charge. Le manager choisit les canaux de chaque client (Politique des clients). HTTPS seulement, certificat vérifié, aucune redirection suivie, adresses internes de la machine refusées. L'adresse et le secret sont chiffrés et ne sont plus réaffichés.")}</p>
        {error && <p className="error" role="alert">{error}</p>}
        {items === null && !error && <p className="loading">{tr('Chargement…')}</p>}
        {items?.length === 0 && <p className="muted">{tr('Aucun canal : l’astreinte est inactive pour tous les clients.')}</p>}
        {items?.length > 0 && (
          <div className="table-wrap" tabIndex={0} role="region" aria-label={tr("Liste des canaux d'astreinte")}><table className="grid">
            <thead><tr><th scope="col">{tr('Nom')}</th><th scope="col">{tr('Type')}</th><th scope="col">{tr('Adresse')}</th><th scope="col">{tr('Options')}</th><th scope="col">{tr('Créé le')}</th><th scope="col">{tr('Actions')}</th></tr></thead>
            <tbody>{items.map((c) => <Canal key={c.id} c={c} reload={load} />)}</tbody>
          </table></div>
        )}
      </section>
      <section className="card section" aria-label={tr('Ajouter un canal')}>
        <h2>{tr('Ajouter un canal')}</h2>
        <form onSubmit={create} className="stack">
          <div className="grid2">
            <label>{tr('Nom')}<input name="name" required minLength={2} maxLength={80} placeholder={tr('ex. astreinte-soc')} /></label>
            <label>{tr('Type')}<select value={kind} onChange={(e) => setKind(e.target.value)}>
              {Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select></label>
          </div>
          <label>{kind === 'email' ? tr("Adresse courriel de l'équipe") : tr('Adresse du webhook (https://…)')}
            <input name="target" required type={kind === 'email' ? 'email' : 'url'} maxLength={1000} autoComplete="off" spellCheck={false} /></label>
          {kind === 'webhook_json' && (
            <label>{tr('Secret de signature (facultatif)')}
              <input name="secret" type="password" maxLength={200} autoComplete="new-password" aria-describedby="canal-secret-aide" />
              <span className="field-hint" id="canal-secret-aide">{tr('Chaque envoi porte X-Keryx-Timestamp et X-Keryx-Signature : sha256=HMAC(secret, « horodatage.corps »).')}</span>
            </label>
          )}
          <label className="check"><input type="checkbox" name="include_title" />{' '}{tr('Inclure le titre du ticket (il part chez le service appelé ; par défaut : référence, client, criticité et lien seulement)')}</label>
          <div><button type="submit" className="primary">{tr('Ajouter le canal')}</button></div>
          <ActionStatus state={status} />
        </form>
      </section>
    </>
  )
}
