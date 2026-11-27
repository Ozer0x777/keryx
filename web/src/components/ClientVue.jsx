import { useState } from 'react'
import { api } from '../api.js'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'
import { ActionStatus, useActionStatus } from './ActionStatus.jsx'
import Section from './Section.jsx'

// Portail client : ce que le client lit en premier, en mots de client (revue de l'interface, C02 à C11).

// Statut en mots de client (C03). Le statut ISO/IEC 27035 de l'équipe ne change pas.
export function statutClient(t, aDecider) {
  if (aDecider) return { cls: 'vous', label: tr('Votre réponse attendue') }
  return {
    nouveau: { cls: 'analyse', label: tr('Le SOC analyse') },
    en_evaluation: { cls: 'analyse', label: tr('Le SOC analyse') },
    en_reponse: { cls: 'reponse', label: tr('Réponse en cours') },
    cloture: { cls: 'resolu', label: tr('Résolu') },
    retour_experience: { cls: 'resolu', label: tr('Résolu') },
    faux_positif: { cls: 'clos', label: tr('Clos : fausse alerte') },
  }[t.status] || { cls: 'analyse', label: t.status }
}

export function StatutClient({ t, aDecider }) {
  const s = statutClient(t, aDecider)
  return <span className={`st-client ${s.cls}`}>{s.label}</span>
}

// Ce qui attend la réponse du client sur ce ticket : mesures proposées, actions demandées encore à faire.
export function aFaire(t) {
  return [
    ...(t.mesures || []).filter((m) => m.etat === 'proposee').map((m) => ({ kind: 'mesure', ...m })),
    ...(t.actions_client || []).filter((a) => a.etat === 'a_faire').map((a) => ({ kind: 'action', ...a })),
  ]
}

// « À faire de votre côté » (C07) : en tête de la fiche du client, avec les boutons.
export function ClientTodo({ t, enc, run, open }) {
  const [status, track] = useActionStatus()
  const items = aFaire(t)
  if (!items.length) return null
  const mesure = (m, etat) => track(() => run(() => api(`/tickets/${enc}/mesures/${m.id}`, { method: 'PATCH', json: { etat } }), tr('Votre décision est enregistrée.')))
  const action = (a) => track(() => run(() => api(`/tickets/${enc}/actions-client/${a.id}`, { method: 'PATCH', json: { etat: 'faite' } }), tr('Action marquée comme faite.')))
  return (
    <section className="card section client-todo" aria-label={tr('À faire de votre côté')}>
      <h2>{tr('À faire de votre côté')}</h2>
      <ul className="todo-list">
        {items.map((x) => (
          <li key={`${x.kind}-${x.id}`}>
            <div>
              <strong>{x.kind === 'mesure' ? (x.type === 'urgence' ? tr("Autoriser la procédure d'urgence : {l}", { l: x.libelle }) : tr('Autoriser : {l}', { l: x.libelle })) : x.libelle}</strong>
              <span className="muted small">{x.kind === 'mesure' ? tr('Mesure proposée par le SOC le {d}', { d: formatUtc(x.cree_le) }) : tr('Action demandée par le SOC le {d}', { d: formatUtc(x.cree_le) })}</span>
            </div>
            {open && (x.kind === 'mesure' ? (
              <span className="row gap">
                <button type="button" onClick={() => mesure(x, 'refusee')}>{tr('Refuser')}</button>
                <button type="button" className="primary" onClick={() => mesure(x, 'acceptee')}>{tr('Autoriser')}</button>
              </span>
            ) : <button type="button" onClick={() => action(x)}>{tr("C'est fait")}</button>)}
          </li>
        ))}
      </ul>
      <ActionStatus state={status} />
    </section>
  )
}

// Frise d'avancement (C06) : les phases ISO/IEC 27035 dites simplement. Les échéances internes ne sont pas montrées.
const ETAPES = [
  ['detecte', () => tr('Détecté')], ['analyse', () => tr('Analysé')], ['reponse', () => tr('Réponse')], ['resolu', () => tr('Résolu')],
]
const RANG = { nouveau: 0, en_evaluation: 1, en_reponse: 2, faux_positif: 3, cloture: 3, retour_experience: 3 }
export function Frise({ t }) {
  const r = RANG[t.status] ?? 0
  return (
    <ol className="frise" aria-label={tr('Avancement')}>
      {ETAPES.map(([k, label], i) => (
        <li key={k} className={i < r ? 'done' : i === r ? 'now' : ''} aria-current={i === r ? 'step' : undefined}>
          <b>{label()}</b>
          <span>{i === 0 ? formatUtc(t.detected_at) : i < r ? tr('fait') : i === r ? (t.status === 'faux_positif' ? tr('fausse alerte') : tr('en cours')) : ''}</span>
        </li>
      ))}
    </ol>
  )
}

// « Ce qui se passe » (C05) : résumé écrit pour le client par l'analyste (texte brut).
export function CeQuiSePasse({ t }) {
  return (
    <section className="card section ce-qui-se-passe" aria-label={tr('Ce qui se passe')}>
      <h2>{tr('Ce qui se passe')}</h2>
      {t.resume_client
        ? <><p className="prewrap">{t.resume_client}</p><p className="muted small">{tr('Rédigé par le SOC, mis à jour le {d}.', { d: formatUtc(t.resume_client_le) })}</p></>
        : <p className="muted">{tr("Le SOC n'a pas encore rédigé de résumé pour cet incident. Les échanges ci-dessous et les détails techniques en fin de page restent à jour.")}</p>}
    </section>
  )
}

// Équipe : titre et résumé destinés au client (C04, C05), affichés en tête de son portail.
export function VueClientEditor({ t, enc, run, open }) {
  const [titre, setTitre] = useState(t.titre_client || '')
  const [resume, setResume] = useState(t.resume_client || '')
  const [status, track] = useActionStatus()
  const changed = titre !== (t.titre_client || '') || resume !== (t.resume_client || '')
  const save = () => track(() => run(() => api(`/tickets/${enc}/vue-client`, { method: 'PUT', json: { titre_client: titre, resume_client: resume } }), tr('Vue du client enregistrée.')))
  return (
    <Section id="vue-client" title={tr('Ce que lit le client')} filled={Boolean(t.titre_client || t.resume_client)}
      summary={t.resume_client ? tr('résumé à jour du {d}', { d: formatUtc(t.resume_client_le) }) : tr('pas de résumé')}>
      <p className="field-hint">{tr('En tête du portail du client, en mots simples. Sans titre, le client voit le titre Wazuh ; la description technique reste dans ses détails techniques.')}</p>
      <label>{tr('Titre pour le client')}
        <input value={titre} maxLength={300} disabled={!open} placeholder={tr('ex. Tentatives de connexion répétées sur un serveur')} onChange={(e) => setTitre(e.target.value)} /></label>
      <label>{tr('Ce qui se passe (résumé pour le client)')}
        <textarea rows={4} value={resume} maxLength={10000} disabled={!open} onChange={(e) => setResume(e.target.value)}
          placeholder={tr('ex. Un programme inconnu s\'est lancé sur le serveur et a tenté de joindre une adresse extérieure. Aucune donnée sortie constatée à ce stade.')} /></label>
      {open && <div><button type="button" className="primary" disabled={!changed} onClick={save}>{tr('Enregistrer')}</button></div>}
      <ActionStatus state={status} />
    </Section>
  )
}
