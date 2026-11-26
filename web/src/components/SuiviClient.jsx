import { useState } from 'react'
import { api } from '../api.js'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'
import { ActionStatus, useActionStatus } from './ActionStatus.jsx'
import Section from './Section.jsx'

// Suivi d'un ticket par le client (PDIS IV.2.3.l) : état de son côté, demande de clôture ou de réouverture, actions
// que l'équipe lui demande. Le client les modifie ; l'équipe les voit, ajoute des actions et refuse une demande.
export const ETATS_CLIENT = { pris_en_compte: tr('Pris en compte'), en_cours: tr('En cours de traitement chez nous'), traite: tr('Traité de notre côté') }
export const ETATS_ACTION = { a_faire: tr('À faire'), faite: tr('Faite'), impossible: tr('Impossible') }
const DEMANDES = { cloture: tr('clôture'), reouverture: tr('réouverture') }

function ActionLigne({ a, enc, isClient, run }) {
  const [etat, setEtat] = useState(a.etat)
  const [commentaire, setCommentaire] = useState('')
  const [status, track] = useActionStatus()
  const save = () => track(() => run(() => api(`/tickets/${enc}/actions-client/${a.id}`, { method: 'PATCH', json: { etat, commentaire } }), tr('Action mise à jour.')))
  return (
    <li>
      <strong>{a.libelle}</strong> <span className="pill">{ETATS_ACTION[a.etat]}</span>
      <span className="muted small"> · {tr('demandée par {who} le {d}', { who: a.cree_par, d: formatUtc(a.cree_le) })}{a.maj_le ? ` · ${tr('mise à jour par {who} le {d}', { who: a.maj_par, d: formatUtc(a.maj_le) })}` : ''}</span>
      {a.commentaire && <div className="small">{a.commentaire}</div>}
      {isClient && (
        <div className="row wrap gap">
          <label>{tr('État')}<select value={etat} onChange={(e) => setEtat(e.target.value)}>{Object.entries(ETATS_ACTION).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label>{tr('Commentaire')}<input value={commentaire} maxLength={2000} onChange={(e) => setCommentaire(e.target.value)} /></label>
          <button type="button" onClick={save} disabled={etat === a.etat && !commentaire.trim()}>{tr('Mettre à jour')}</button>
          <ActionStatus state={status} />
        </div>
      )}
    </li>
  )
}

export default function SuiviClient({ t, enc, isClient, run, open }) {
  const s = t.suivi_client || {}
  const [etat, setEtat] = useState(s.etat || '')
  const [commentaire, setCommentaire] = useState('')
  const [libelle, setLibelle] = useState('')
  const [motif, setMotif] = useState('')
  const [status, track] = useActionStatus()
  const envoyer = (json, ok) => track(() => run(() => api(`/tickets/${enc}/etat-client`, { method: 'POST', json: { ...json, commentaire } }), ok))
  return (
    <Section id="suivi-client" title={isClient ? tr('Votre suivi') : tr('Suivi par le client')}
      summary={s.demande ? <span className="pill warn">{tr('Demande de {d}', { d: DEMANDES[s.demande] })}</span> : (s.etat ? ETATS_CLIENT[s.etat] : null)}>
      <p>{s.etat ? tr('État côté client : {e}', { e: ETATS_CLIENT[s.etat] }) : tr('État côté client : non renseigné')}
        {s.maj_le && <span className="muted small"> · {formatUtc(s.maj_le)}</span>}</p>
      {s.demande && <p className="banner warn">{tr('Le client demande la {d} du ticket.', { d: DEMANDES[s.demande] })}</p>}
      {isClient && (
        <div className="stack">
          <div className="row wrap gap">
            <label>{tr('État de votre côté')}<select value={etat} onChange={(e) => setEtat(e.target.value)}>
              <option value="" disabled>{tr('Choisir')}</option>
              {Object.entries(ETATS_CLIENT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            <label>{tr('Commentaire (facultatif)')}<input value={commentaire} maxLength={2000} onChange={(e) => setCommentaire(e.target.value)} /></label>
          </div>
          <div className="row wrap gap">
            <button type="button" className="primary" disabled={!etat || etat === s.etat} onClick={() => envoyer({ etat }, tr('État enregistré.'))}>{tr("Enregistrer l'état")}</button>
            {open && !s.demande && <button type="button" onClick={() => envoyer({ demande: 'cloture' }, tr('Demande de clôture envoyée.'))}>{tr('Demander la clôture')}</button>}
            {!open && !s.demande && <button type="button" onClick={() => envoyer({ demande: 'reouverture' }, tr('Demande de réouverture envoyée.'))}>{tr('Demander la réouverture')}</button>}
          </div>
        </div>
      )}
      {!isClient && s.demande && (
        <div className="row wrap gap">
          <label>{tr('Motif du refus (10 caractères au moins, visible du client)')}<input value={motif} maxLength={2000} onChange={(e) => setMotif(e.target.value)} /></label>
          <button type="button" disabled={motif.trim().length < 10} onClick={() => track(() => run(() => api(`/tickets/${enc}/demande-client/refus`, { method: 'POST', json: { motif } }), tr('Demande refusée.')))}>{tr('Refuser la demande')}</button>
          <span className="muted small">{tr('Pour accepter une demande de clôture : clore le ticket.')}</span>
        </div>
      )}
      <h3>{tr('Actions demandées au client')}</h3>
      {(t.actions_client || []).length === 0 ? <p className="muted">{tr('Aucune action demandée.')}</p>
        : <ul className="stack">{t.actions_client.map((a) => <ActionLigne key={a.id} a={a} enc={enc} isClient={isClient} run={run} />)}</ul>}
      {!isClient && open && (
        <div className="row wrap gap">
          <label>{tr('Nouvelle action demandée au client')}<input value={libelle} maxLength={500} onChange={(e) => setLibelle(e.target.value)} /></label>
          <button type="button" disabled={libelle.trim().length < 3} onClick={async () => { if (await track(() => run(() => api(`/tickets/${enc}/actions-client`, { method: 'POST', json: { libelle } }), tr('Action ajoutée.')))) setLibelle('') }}>{tr('Demander cette action')}</button>
        </div>
      )}
      <ActionStatus state={status} />
    </Section>
  )
}
