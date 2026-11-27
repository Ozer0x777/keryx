import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'
import { ActionStatus, useActionStatus } from './ActionStatus.jsx'
import Section from './Section.jsx'

// Réponse aux incidents (PRIS v3.2) : posture et discrétion (VI.3.b), compréhension structurée (VI.5.3.e), mesures
// d'endiguement (VI.5.4), cadre du rapport d'analyse (VI.7). Texte brut, jamais interprété comme du HTML.
export const DISCRETION = { eleve: tr('Élevée'), moyen: tr('Moyenne'), faible: tr('Faible') }
export const MENACE = { strategique: tr('Stratégique'), systemique: tr('Systémique'), hacktiviste: tr('Hacktiviste'), isolee: tr('Isolée'), indeterminee: tr('Indéterminée') }
export const PRESENCE = { oui: tr('Oui'), non: tr('Non'), inconnu: tr('Inconnu') }
export const ROLES_EQUIPE = { responsable_equipe: tr("Responsable d'équipe"), pilote_investigation: tr("Pilote d'investigation"), analyste_reseau: tr('Analyste réseau'), analyste_systeme: tr('Analyste système'), analyste_codes: tr('Analyste de codes malveillants'), gestionnaire_crise: tr('Gestionnaire de crise'), expert: tr('Expert') }
export const ETATS_MESURE = { proposee: tr('Proposée'), acceptee: tr('Acceptée par le commanditaire'), refusee: tr('Refusée par le commanditaire'), appliquee: tr('Appliquée'), levee: tr('Levée') }

export const CHAMPS = {
  posture: [
    ['discretion', tr("Niveau de discrétion vis-à-vis de l'attaquant"), 'choix', DISCRETION],
    ['demarche', tr('Démarche générale de réponse'), 'texte'], ['jalons', tr('Grands jalons et calendrier'), 'texte'],
    ['activites', tr('Activités de réponse à réaliser'), 'texte'], ['informations_a_collecter', tr('Informations à collecter et modes opératoires'), 'texte'],
    ['effectifs', tr("Nombre d'analystes et d'experts"), 'ligne'], ['validee_par', tr('Posture validée par (correspondant du commanditaire)'), 'ligne'],
    ['validee_le', tr('Validée le'), 'ligne'],
  ],
  comprehension: [
    ['attaquant_present', tr("L'attaquant est-il toujours présent ?"), 'choix', PRESENCE],
    ['mo_compromission_initiale', tr('Mode opératoire : compromission initiale'), 'texte'], ['mo_maintien', tr('Mode opératoire : maintien dans le SI'), 'texte'],
    ['mo_dissimulation', tr('Mode opératoire : dissimulation'), 'texte'], ['mo_cartographie', tr('Mode opératoire : cartographie du SI'), 'texte'],
    ['mo_elevation_privileges', tr('Mode opératoire : élévation de privilèges'), 'texte'], ['mo_controle', tr('Mode opératoire : contrôle des ressources compromises'), 'texte'],
    ['mo_collecte', tr("Mode opératoire : collecte d'informations"), 'texte'], ['mo_exfiltration', tr("Mode opératoire : exfiltration d'informations"), 'texte'],
    ['potentiel_attaque', tr("Potentiel d'attaque estimé"), 'texte'], ['niveau_menace', tr('Niveau de menace estimé'), 'choix', MENACE],
    ['objectifs_attaquant', tr("Objectifs supposés de l'attaquant"), 'texte'],
    ['vecteur_initial', tr('Vecteur initial de compromission'), 'texte'], ['privileges_obtenus', tr("Niveau de privilège obtenu par l'attaquant"), 'texte'],
    ['ressources_compromises', tr('Ressources compromises'), 'texte'], ['comptes_compromis', tr("Comptes compromis, en particulier d'administration"), 'texte'],
  ],
  rapport: [
    ['qualifiee', tr('Prestation qualifiée'), 'oui_non'], ['niveau', tr('Niveau de qualification'), 'choix', { substantiel: tr('Substantiel'), eleve: tr('Élevé') }],
    ['activites', tr('Activités de réponse'), 'multi', { REC: 'REC', INV: 'INV', CODE: 'CODE', PCI: 'PCI', CRISE: 'CRISE' }],
    ['analyse', tr("Type d'analyse"), 'multi', { systeme: tr('Système'), reseau: tr('Réseau') }],
    ['objectifs', tr('Objectifs'), 'texte'], ['criteres', tr('Critères'), 'texte'], ['perimetre_prestation', tr('Périmètre de la prestation'), 'texte'],
    ['modalites', tr('Modalités particulières'), 'texte'], ['dates_lieux', tr('Dates et lieux de la prestation'), 'texte'],
    ['documents', tr('Documents de référence (référence, version, date)'), 'texte'],
    ['synthese_manageriale', tr('Synthèse managériale (compréhensible par un non-expert)'), 'texte'],
    ['risques_critiques', tr('Risques critiques'), 'texte'], ['endiguement_recommande', tr("Principales mesures d'endiguement recommandées"), 'texte'],
    ['reserves', tr('Réserves sur les résultats'), 'texte'], ['ioc_recherches', tr('Indicateurs de compromission recherchés'), 'texte'],
    ['elements_collectes', tr('Éléments collectés et analysés'), 'texte'], ['resultats', tr('Résultats des activités de réponse'), 'texte'],
    ['actions_a_poursuivre', tr('[Crise] Actions à initier ou à poursuivre'), 'texte'], ['points_amelioration', tr('[Crise] Points positifs et à améliorer'), 'texte'],
  ],
}

function Bloc({ t, enc, run, bloc, titre, aide, editable }) {
  const init = (t.pris || {})[bloc] || {}
  const [v, setV] = useState(init)
  const [status, track] = useActionStatus()
  const changed = JSON.stringify(v) !== JSON.stringify(init)
  const save = () => {
    const json = Object.fromEntries(CHAMPS[bloc].map(([k]) => [k, v[k] ?? '']).filter(([k, x]) => JSON.stringify(x) !== JSON.stringify(init[k] ?? '')))
    return track(() => run(() => api(`/tickets/${enc}/pris/${bloc}`, { method: 'PUT', json }), tr('Enregistré.')))
  }
  const set = (k, x) => setV({ ...v, [k]: x })
  return (
    <Section id={`pris-${bloc}`} title={titre} summary={Object.keys(init).length ? tr('{n} champ(s) renseigné(s)', { n: Object.keys(init).length }) : null}>
      {aide && <p className="field-hint">{aide}</p>}
      <div className="stack">
        {CHAMPS[bloc].map(([k, label, sorte, choix]) => {
          const id = `${bloc}-${k}`
          if (sorte === 'choix') return (
            <label key={k} htmlFor={id}>{label}<select id={id} value={v[k] || ''} disabled={!editable} onChange={(e) => set(k, e.target.value)}>
              <option value="">{tr('Non renseigné')}</option>
              {Object.entries(choix).map(([c, l]) => <option key={c} value={c}>{l}</option>)}</select></label>)
          if (sorte === 'oui_non') return (
            <label key={k} className="check"><input type="checkbox" checked={Boolean(v[k])} disabled={!editable} onChange={(e) => set(k, e.target.checked)} />{' '}{label}</label>)
          if (sorte === 'multi') return (
            <fieldset key={k}><legend>{label}</legend>{Object.entries(choix).map(([c, l]) => (
              <label key={c} className="check"><input type="checkbox" checked={(v[k] || []).includes(c)} disabled={!editable}
                onChange={(e) => set(k, e.target.checked ? [...(v[k] || []), c] : (v[k] || []).filter((x) => x !== c))} />{' '}{l}</label>))}</fieldset>)
          if (sorte === 'ligne') return <label key={k} htmlFor={id}>{label}<input id={id} value={v[k] || ''} maxLength={200} disabled={!editable} onChange={(e) => set(k, e.target.value)} /></label>
          return <label key={k} htmlFor={id}>{label}<textarea id={id} rows={2} value={v[k] || ''} maxLength={20000} disabled={!editable} onChange={(e) => set(k, e.target.value)} /></label>
        })}
        {editable && <div><button type="button" className="primary" disabled={!changed} onClick={save}>{tr('Enregistrer')}</button></div>}
        <ActionStatus state={status} />
      </div>
    </Section>
  )
}

function Equipe({ t, enc, run, editable }) {
  const r = (t.pris || {}).rapport || {}
  const [equipe, setEquipe] = useState(r.equipe || [])
  const [inter, setInter] = useState(r.interlocuteurs || [])
  const [status, track] = useActionStatus()
  const save = () => track(() => run(() => api(`/tickets/${enc}/pris/rapport`, { method: 'PUT', json: { equipe, interlocuteurs: inter } }), tr('Enregistré.')))
  const ligne = (liste, setListe, i, k, x) => setListe(liste.map((y, j) => (j === i ? { ...y, [k]: x } : y)))
  return (
    <Section id="pris-equipe" title={tr("Équipe de réponse et interlocuteurs (rapport d'analyse)")} summary={equipe.length ? tr('{n} membre(s)', { n: equipe.length }) : null}>
      <h3>{tr('Équipe de réponse')}</h3>
      {equipe.map((m, i) => (
        <div key={i} className="row wrap gap">
          <label>{tr('Nom')}<input value={m.nom || ''} maxLength={200} disabled={!editable} onChange={(e) => ligne(equipe, setEquipe, i, 'nom', e.target.value)} /></label>
          <label>{tr('Coordonnées')}<input value={m.coordonnees || ''} maxLength={300} disabled={!editable} onChange={(e) => ligne(equipe, setEquipe, i, 'coordonnees', e.target.value)} /></label>
          <label>{tr('Rôle')}<select value={m.role || 'analyste_systeme'} disabled={!editable} onChange={(e) => ligne(equipe, setEquipe, i, 'role', e.target.value)}>
            {Object.entries(ROLES_EQUIPE).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
          <label>{tr('Activités réalisées')}<input value={m.activites || ''} maxLength={500} disabled={!editable} onChange={(e) => ligne(equipe, setEquipe, i, 'activites', e.target.value)} /></label>
          {editable && <button type="button" onClick={() => setEquipe(equipe.filter((_, j) => j !== i))}>{tr('Retirer')}</button>}
        </div>
      ))}
      {editable && <button type="button" onClick={() => setEquipe([...equipe, { role: 'analyste_systeme' }])}>{tr('Ajouter un membre')}</button>}
      <h3>{tr('Personnes avec qui le prestataire a interagi')}</h3>
      {inter.map((p, i) => (
        <div key={i} className="row wrap gap">
          <label>{tr('Nom')}<input value={p.nom || ''} maxLength={200} disabled={!editable} onChange={(e) => ligne(inter, setInter, i, 'nom', e.target.value)} /></label>
          <label>{tr('Fonction')}<input value={p.fonction || ''} maxLength={200} disabled={!editable} onChange={(e) => ligne(inter, setInter, i, 'fonction', e.target.value)} /></label>
          <label>{tr('Entité')}<input value={p.entite || ''} maxLength={200} disabled={!editable} onChange={(e) => ligne(inter, setInter, i, 'entite', e.target.value)} /></label>
          {editable && <button type="button" onClick={() => setInter(inter.filter((_, j) => j !== i))}>{tr('Retirer')}</button>}
        </div>
      ))}
      {editable && <div className="row wrap gap"><button type="button" onClick={() => setInter([...inter, {}])}>{tr('Ajouter une personne')}</button>
        <button type="button" className="primary" onClick={save}>{tr('Enregistrer')}</button></div>}
      <ActionStatus state={status} />
    </Section>
  )
}

export function Mesures({ t, enc, run, isClient, open }) {
  const [libelle, setLibelle] = useState('')
  const [type, setType] = useState('endiguement')
  const [status, track] = useActionStatus()
  const [auteur, setAuteur] = useState({})       // décision rapportée par l'équipe : qui l'a prise, par mesure
  const maj = (m, etat, extra = {}) => track(() => run(() => api(`/tickets/${enc}/mesures/${m.id}`, { method: 'PATCH', json: { etat, ...extra } }), tr('Mesure mise à jour.')))
  const liste = t.mesures || []
  if (isClient && liste.length === 0) return null
  return (
    <Section id="mesures" title={tr("Mesures d'endiguement et procédures d'urgence")} summary={liste.filter((m) => m.etat === 'proposee').length ? <span className="pill warn">{tr('{n} à décider', { n: liste.filter((m) => m.etat === 'proposee').length })}</span> : (liste.length || null)}>
      <p className="field-hint">{isClient
        ? tr("Le SOC vous propose ces mesures pour contenir l'incident. La décision vous revient : acceptez ou refusez chacune.")
        : tr("Proposées au commanditaire, qui décide (PRIS VI.5.4) ; à réévaluer au fil de l'incident.")}</p>
      {liste.length === 0 ? <p className="muted">{tr('Aucune mesure proposée.')}</p> : (
        <ul className="stack">{liste.map((m) => (
          <li key={m.id}>
            <strong>{m.libelle}</strong> {m.type === 'urgence' && <span className="pill danger">{tr('Bouton rouge')}</span>} <span className="pill">{ETATS_MESURE[m.etat]}</span>
            <div className="muted small">{tr('proposée par {who} le {d}', { who: m.cree_par, d: formatUtc(m.cree_le) })}{m.decision_par ? ` · ${tr('décision : {who}', { who: m.decision_par })}` : ''}{m.maj_le ? ` · ${formatUtc(m.maj_le)}` : ''}</div>
            {m.commentaire && <div className="small">{m.commentaire}</div>}
            <div className="row wrap gap">
              {isClient && m.etat === 'proposee' && <>
                <button type="button" className="primary" onClick={() => maj(m, 'acceptee')}>{tr('Accepter')}</button>
                <button type="button" onClick={() => maj(m, 'refusee')}>{tr('Refuser')}</button></>}
              {!isClient && m.etat === 'proposee' && <>
                <label>{tr('Décision rapportée, prise par')}<input value={auteur[m.id] || ''} maxLength={200} onChange={(e) => setAuteur({ ...auteur, [m.id]: e.target.value })} /></label>
                <button type="button" disabled={!(auteur[m.id] || '').trim()} onClick={() => maj(m, 'acceptee', { decision_par: auteur[m.id] })}>{tr('Acceptée')}</button>
                <button type="button" disabled={!(auteur[m.id] || '').trim()} onClick={() => maj(m, 'refusee', { decision_par: auteur[m.id] })}>{tr('Refusée')}</button></>}
              {!isClient && m.etat === 'acceptee' && <button type="button" onClick={() => maj(m, 'appliquee')}>{tr('Marquer appliquée')}</button>}
              {!isClient && m.etat === 'appliquee' && <button type="button" onClick={() => maj(m, 'levee')}>{tr('Marquer levée')}</button>}
              {!isClient && open && ['refusee', 'levee'].includes(m.etat) && <button type="button" onClick={() => maj(m, 'proposee')}>{tr('Proposer de nouveau')}</button>}
            </div>
          </li>
        ))}</ul>
      )}
      {!isClient && open && (
        <div className="row wrap gap">
          <label>{tr('Nouvelle mesure')}<input value={libelle} maxLength={1000} onChange={(e) => setLibelle(e.target.value)} /></label>
          <label>{tr('Type')}<select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="endiguement">{tr('Endiguement')}</option><option value="urgence">{tr('Procédure d’urgence (bouton rouge)')}</option></select></label>
          <button type="button" disabled={libelle.trim().length < 3} onClick={async () => { if (await track(() => run(() => api(`/tickets/${enc}/mesures`, { method: 'POST', json: { type, libelle } }), tr('Mesure proposée.')))) setLibelle('') }}>{tr('Proposer')}</button>
        </div>
      )}
      <ActionStatus state={status} />
    </Section>
  )
}

export default function Pris({ t, enc, run, open }) {
  const editable = t.status !== 'faux_positif'
  return (
    <section className="card section" aria-label={tr('Réponse aux incidents')}>
      <header className="section-head"><h2>{tr('Réponse aux incidents')}</h2>
        <div className="row wrap gap">
          <Link to={`/tickets/${enc}/point-situation`}>{tr('Point de situation')}</Link>
          <Link to={`/tickets/${enc}/rapport-analyse`}>{tr("Rapport d'analyse")}</Link>
        </div></header>
      <div className="section-body stack">
        <Bloc t={t} enc={enc} run={run} bloc="posture" titre={tr('Posture')} editable={editable}
          aide={tr("En discrétion élevée, aucune recherche en source ouverte ne part de Keryx (VirusTotal refusé) ; à faire valider par le correspondant du commanditaire et à réviser.")} />
        <Bloc t={t} enc={enc} run={run} bloc="comprehension" titre={tr("Compréhension de l'incident")} editable={editable}
          aide={tr('Synthèse tenue à jour (PRIS VI.5.3.e), complète la chronologie et le périmètre de la synthèse.')} />
        <Mesures t={t} enc={enc} run={run} isClient={false} open={open} />
        <Bloc t={t} enc={enc} run={run} bloc="rapport" titre={tr("Cadre du rapport d'analyse")} editable={editable}
          aide={tr("Champs du rapport d'analyse (PRIS VI.7) ; les registres, la synthèse, la crise et le retour d'expérience sont repris automatiquement.")} />
        <Equipe t={t} enc={enc} run={run} editable={editable} />
      </div>
    </section>
  )
}
