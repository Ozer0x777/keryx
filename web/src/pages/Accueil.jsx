import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import { ActionStatus, useActionStatus } from '../components/ActionStatus.jsx'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'
import { dureeLisible } from '../dates.js'

// Accueil du portail client (C01) : ce qui attend sa réponse, quelques chiffres, les dernières nouvelles du SOC, son
// parc. Tout vient de /client/accueil : ses clients seulement, jamais les échéances internes de l'équipe.
const STATUT = { en_evaluation: () => tr('Le SOC analyse'), en_reponse: () => tr('Réponse en cours'), cloture: () => tr('Résolu'),
  retour_experience: () => tr('Résolu'), faux_positif: () => tr('Clos : fausse alerte'), nouveau: () => tr('Le SOC analyse') }

// Une action visible du registre, dite en une phrase de client.
function phrase(n) {
  const d = n.details || {}
  switch (n.action) {
    case 'statut': return tr('Nouveau statut : {s}.', { s: (STATUT[d.to] || (() => d.to))() })
    case 'mesure_proposee': return tr('Le SOC propose une mesure : {l}.', { l: d.libelle })
    case 'mesure_acceptee': return tr('Mesure autorisée : {l}.', { l: d.libelle })
    case 'mesure_refusee': return tr('Mesure refusée : {l}.', { l: d.libelle })
    case 'mesure_appliquee': return tr('Mesure appliquée : {l}.', { l: d.libelle })
    case 'mesure_levee': return tr('Mesure levée : {l}.', { l: d.libelle })
    case 'action_client_demandee': return tr('Le SOC vous demande : {l}.', { l: d.libelle })
    case 'action_client_maj': return tr('Action mise à jour : {l}.', { l: d.libelle })
    case 'vue_client': return tr('Le SOC a mis à jour le résumé.')
    case 'etat_client': return tr('Votre suivi a été mis à jour.')
    default: return tr('Mise à jour du dossier.')
  }
}

export default function Accueil() {
  const { me } = useAuth()
  const [d, setD] = useState(null)
  const [error, setError] = useState('')
  const [status, track] = useActionStatus()
  const load = useCallback(() => api('/client/accueil').then(setD).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])
  const act = (fn, ok) => track(async () => { const r = await fn(); await load(); return r }, ok)
  const decide = (x, etat) => act(() => api(`/tickets/${encodeURIComponent(x.ref)}/mesures/${x.id}`, { method: 'PATCH', json: { etat } }), tr('Votre décision est enregistrée.'))
  const faite = (x) => act(() => api(`/tickets/${encodeURIComponent(x.ref)}/actions-client/${x.id}`, { method: 'PATCH', json: { etat: 'faite' } }), tr('Action marquée comme faite.'))
  if (error) return <p className="error" role="alert">{error}</p>
  if (!d) return <p className="loading">{tr('Chargement…')}</p>
  const c = d.chiffres
  const prenom = me.display_name.split(/\s+/)[0]
  return (
    <>
      <header className="page-head"><div><h1>{tr('Bonjour {p}', { p: prenom })}</h1>
        <p className="muted">{me.clients.map((x) => x.name).join(', ')} · {tr('surveillé par votre SOC')}</p></div></header>
      {d.a_faire.length > 0 ? (
        <section className="card section client-todo" aria-label={tr('À faire de votre côté')}>
          <h2>{tr('À faire de votre côté')}</h2>
          <ul className="todo-list">
            {d.a_faire.map((x) => (
              <li key={`${x.kind}-${x.id}`}>
                <div>
                  <strong>{x.kind === 'mesure' ? tr('Autoriser : {l}', { l: x.libelle }) : x.libelle}</strong>
                  <span className="muted small"><Link to={`/tickets/${encodeURIComponent(x.ref)}`} className="mono">{x.ref}</Link> {x.titre} · {formatUtc(x.cree_le)}</span>
                </div>
                {x.kind === 'mesure' ? (
                  <span className="row gap"><button type="button" onClick={() => decide(x, 'refusee')}>{tr('Refuser')}</button>
                    <button type="button" className="primary" onClick={() => decide(x, 'acceptee')}>{tr('Autoriser')}</button></span>
                ) : <button type="button" onClick={() => faite(x)}>{tr("C'est fait")}</button>}
              </li>
            ))}
          </ul>
          <ActionStatus state={status} />
        </section>
      ) : <p className="banner ok">{tr("Rien n'attend votre réponse pour le moment.")}</p>}
      <section className="stats" aria-label={tr('Chiffres')}>
        <Link className={`card stat${c.attente ? ' hot' : ''}`} to="/tickets?a_decider=1"><span className="muted">{tr('Attendent votre réponse')}</span><strong>{c.attente}</strong></Link>
        <Link className="card stat" to="/tickets?status=nouveau%2Cen_evaluation%2Cen_reponse"><span className="muted">{tr('En cours au SOC')}</span><strong>{c.en_cours}</strong><span className="muted small">{tr('dont {n} critique(s)', { n: c.critiques })}</span></Link>
        <Link className="card stat" to="/tickets?status=cloture%2Cretour_experience%2Cfaux_positif"><span className="muted">{tr('Résolus ce mois-ci')}</span><strong>{c.resolus_mois}</strong>
          <span className="muted small">{c.delai_moyen_h == null ? '' : tr('en {d} en moyenne', { d: dureeLisible(c.delai_moyen_h * 3600) })}</span></Link>
        <Link className="card stat" to="/parc"><span className="muted">{tr('Machines surveillées')}</span><strong>{d.parc.total}</strong><span className="muted small">{tr('{n} hors ligne', { n: d.parc.hors_ligne.length })}</span></Link>
      </section>
      <div className="grid2 dash">
        <section className="card section" aria-label={tr('Dernières nouvelles du SOC')}>
          <h2>{tr('Dernières nouvelles du SOC')}</h2>
          {d.nouvelles.length === 0 ? <p className="muted">{tr('Rien de nouveau.')}</p> : (
            <ul className="feed">{d.nouvelles.map((n, i) => (
              <li key={i}><span className="muted small">{formatUtc(n.ts)}</span>
                <span><Link to={`/tickets/${encodeURIComponent(n.ref)}`} className="mono">{n.ref}</Link> · {phrase(n)}</span></li>
            ))}</ul>
          )}
        </section>
        <section className="card section" aria-label={tr('Votre parc')}>
          <h2>{tr('Votre parc')}</h2>
          {d.parc.total === 0 ? <p className="muted">{tr("Le relevé du parc n'est pas activé pour votre organisation.")}</p> : d.parc.hors_ligne.length === 0
            ? <p>{tr('Vos {n} machines remontent leurs événements au SOC.', { n: d.parc.total })}</p>
            : <p>{tr('{n} machine(s) ne répondent plus : leurs alertes n\'arrivent plus au SOC.', { n: d.parc.hors_ligne.length })} <span className="mono small">{d.parc.hors_ligne.join(', ')}</span></p>}
          <Link to="/parc">{tr('Voir le parc')}</Link>
        </section>
      </div>
    </>
  )
}
