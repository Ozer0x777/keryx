import { useEffect, useState } from 'react'
import { api, downloadBlob } from '../api.js'
import { ActionStatus, useActionStatus } from '../components/ActionStatus.jsx'
import { t as tr } from '../i18n.js'
import { TLPS, formatUtc } from '../labels.js'

// Politique des clients, réglée par le manager pour chacun de ses clients :
// - TLP plancher (ADR-0033) : les tickets et les pièces naissent à ce niveau ; un analyste ne peut pas descendre en
//   dessous. Relever le plancher relève les tickets ouverts qui sont en dessous ; le baisser ne baisse aucun ticket.
// - Astreinte (ADR-0032) : criticités qui préviennent le canal d'astreinte, délai avant escalade, canaux choisis parmi
//   ceux que l'Admin a déclarés ; délai d'acquittement dans le rapport remis au client.
const CRITICITES = ['Critique', 'Élevée', 'Moyenne', 'Faible']

function Client({ c, canaux, onSaved }) {
  const [plancher, setPlancher] = useState(c.tlp_plancher || '')
  const [niveau, setNiveau] = useState(c.niveau_classification_defaut)
  const [versionRegles, setVersionRegles] = useState(c.version_regles || '')
  const [rapport, setRapport] = useState(Boolean(c.acquittement_rapport))
  const [ast, setAst] = useState(c.astreinte)
  const [secours, setSecours] = useState(c.notif_secours.canal_id || '')
  const [essai, setEssai] = useState(c.notif_secours)
  const [essaiStatus, trackEssai, setEssaiStatus] = useActionStatus()
  const [bat, setBat] = useState({ active: c.battement.active, periode_min: c.battement.periode_min, delai_min: c.battement.delai_min })
  const [status, track, setStatus] = useActionStatus()
  const changed = plancher !== (c.tlp_plancher || '') || rapport !== Boolean(c.acquittement_rapport)
    || niveau !== c.niveau_classification_defaut || versionRegles !== (c.version_regles || '')
    || secours !== (c.notif_secours.canal_id || '')
    || JSON.stringify(ast) !== JSON.stringify(c.astreinte)
    || bat.active !== c.battement.active || bat.periode_min !== c.battement.periode_min || bat.delai_min !== c.battement.delai_min
  const set = (patch) => setAst((a) => ({ ...a, ...patch }))
  const crit = (x, on) => set({ criticites: CRITICITES.filter((k) => (k === x ? on : ast.criticites.includes(k))) })
  const save = async () => {
    const json = {
      tlp_plancher: plancher || null, acquittement_rapport: rapport,
      niveau_classification_defaut: niveau, version_regles: versionRegles,
      notif_secours_canal_id: secours || null,
      astreinte_active: ast.active, astreinte_criticites: ast.criticites, astreinte_delais: ast.delais,
      astreinte_canal_id: ast.canal_id || null, escalade_canal_id: ast.escalade_canal_id || null,
      battement_active: bat.active, battement_periode_min: bat.periode_min, battement_delai_min: bat.delai_min,
    }
    const r = await track(() => api(`/politique/${encodeURIComponent(c.key)}`, { method: 'PUT', json }))
    if (!r) return
    onSaved(r)
    setAst(r.astreinte)
    setEssai(r.notif_secours)
    setBat({ active: r.battement.active, periode_min: r.battement.periode_min, delai_min: r.battement.delai_min })
    setStatus({ ok: r.tickets_releves.length
      ? tr('Enregistré : {n} ticket(s) ouvert(s) relevé(s) au plancher.', { n: r.tickets_releves.length })
      : tr('Enregistré.') })
  }
  const id = (x) => `${x}-${c.key}`
  return (
    <section className="card section" aria-label={c.name}>
      <header className="section-head"><h2><span className="mono">{c.key}</span> · {c.name}</h2></header>
      <div className="section-body stack">
        <h3>{tr('Marquage')}</h3>
        <label>{tr('TLP plancher')}
          <select value={plancher} aria-describedby={id('plancher')} onChange={(e) => setPlancher(e.target.value)}>
            <option value="">{tr('Aucun (tickets en TLP:AMBER, sans plancher)')}</option>
            {TLPS.map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <p className="field-hint" id={id('plancher')}>{tr("Les nouveaux tickets et pièces de ce client naissent à ce niveau. Un analyste peut monter, jamais descendre en dessous ; un manager peut descendre un ticket en dessous avec un motif. Relever le plancher relève les tickets ouverts qui sont en dessous ; le baisser ne baisse aucun ticket.")}</p>

        <div className="grid2">
          <label>{tr('Niveau de classification par défaut des incidents')}
            <select value={niveau} onChange={(e) => setNiveau(e.target.value)}>
              {['Non protégé', 'Diffusion Restreinte'].map((x) => <option key={x}>{x}</option>)}
            </select></label>
          <label>{tr('Version du jeu de règles de détection en service')}
            <input value={versionRegles} maxLength={120} placeholder={tr('ex. wazuh-4.9.1 + règles locales 2026-11-20')} onChange={(e) => setVersionRegles(e.target.value)} /></label>
        </div>
        <p className="field-hint">{tr("Reportés sur chaque nouveau ticket (PDIS IV.2.1.w). Seul un manager abaisse ensuite le niveau d'un ticket.")}</p>

        <h3>{tr('Notification du client')}</h3>
        <label>{tr('Moyen secondaire de notification (si le courriel échoue)')}
          <select value={secours} onChange={(e) => setSecours(e.target.value)} disabled={canaux.length === 0}>
            <option value="">{tr('Aucun')}</option>
            {canaux.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
          </select></label>
        <p className={essai.essai_en_retard ? 'banner warn' : 'field-hint'}>
          {essai.canal_id
            ? (essai.teste_le ? tr('Dernier essai réussi : {d}.', { d: formatUtc(essai.teste_le) }) : tr('Jamais essayé.')) + ' ' + tr('Le référentiel demande un essai au moins tous les six mois (PDIS IV.2.3.b).')
            : tr('Le référentiel demande deux moyens de notification (PDIS IV.2.3.b) : choisir un canal déclaré par l\u2019Admin, par exemple un webhook vers un service de SMS.')}
        </p>
        {essai.canal_id && secours === essai.canal_id && (
          <div><button type="button" onClick={async () => {
            const r = await trackEssai(() => api(`/politique/${encodeURIComponent(c.key)}/essai-secours`, { method: 'POST' }))
            if (!r) return
            setEssai(r.notif_secours)
            setEssaiStatus(r.statut === 'envoye' ? { ok: tr('Essai envoyé.') } : { error: tr('Échec de l\u2019essai ({e}{code}).', { e: r.erreur, code: r.code ? `, ${r.code}` : '' }) })
          }}>{tr('Essayer le moyen secondaire')}</button><ActionStatus state={essaiStatus} /></div>
        )}

        <h3>{tr('Astreinte')}</h3>
        {canaux.length === 0
          ? <p className="muted small">{tr("Aucun canal d'astreinte n'est déclaré : l'Admin les ajoute dans Administration > Canaux d'astreinte.")}</p>
          : <>
            <label className="check"><input type="checkbox" checked={ast.active} onChange={(e) => set({ active: e.target.checked })} />{' '}
              {tr("Prévenir l'astreinte à l'ouverture d'un ticket de ce client")}</label>
            <div className="grid2">
              <label>{tr("Canal d'astreinte")}
                <select value={ast.canal_id || ''} onChange={(e) => set({ canal_id: e.target.value || null })}>
                  <option value="">{tr('Aucun')}</option>
                  {canaux.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                </select></label>
              <label>{tr("Canal d'escalade")}
                <select value={ast.escalade_canal_id || ''} onChange={(e) => set({ escalade_canal_id: e.target.value || null })}>
                  <option value="">{tr('Aucun (pas d’escalade)')}</option>
                  {canaux.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                </select></label>
            </div>
            <fieldset>
              <legend>{tr("Criticités qui préviennent l'astreinte, et délai avant escalade sans prise en charge")}</legend>
              <div className="table-wrap" tabIndex={0} role="region" aria-label={tr('Délais d’escalade de {c}', { c: c.name })}><table className="grid">
                <thead><tr><th scope="col">{tr('Criticité')}</th><th scope="col">{tr('Prévient')}</th><th scope="col">{tr('Escalade après (minutes)')}</th></tr></thead>
                <tbody>{CRITICITES.map((k) => (
                  <tr key={k}>
                    <th scope="row">{tr(k)}</th>
                    <td><input type="checkbox" aria-label={tr('{k} : prévenir l’astreinte', { k: tr(k) })} checked={ast.criticites.includes(k)} onChange={(e) => crit(k, e.target.checked)} /></td>
                    <td><input type="number" min={1} max={1440} aria-label={tr('{k} : escalade après (minutes)', { k: tr(k) })} value={ast.delais[k]}
                      onChange={(e) => set({ delais: { ...ast.delais, [k]: Number(e.target.value) || 1 } })} /></td>
                  </tr>
                ))}</tbody>
              </table></div>
            </fieldset>
            <p className="field-hint">{tr("Sans prise en charge, affectation, changement de statut ou qualification dans ce délai, Keryx prévient une fois le canal d'escalade, puis s'arrête. Le message ne contient que la référence, le client, la criticité et le lien, sauf si le canal prévoit le titre.")}</p>
          </>}
        <h3>{tr('Battement de cœur de la chaîne Wazuh')}</h3>
        <label className="check"><input type="checkbox" checked={bat.active} onChange={(e) => setBat({ ...bat, active: e.target.checked })} />{' '}
          {tr("Surveiller le battement de cœur de ce client")}</label>
        <div className="grid2">
          <label>{tr('Période de la tâche planifiée (minutes)')}
            <input type="number" min={1} max={60} value={bat.periode_min} onChange={(e) => setBat({ ...bat, periode_min: Number(e.target.value) || 1 })} /></label>
          <label>{tr("Alerte sans battement après (minutes)")}
            <input type="number" min={2} max={1440} value={bat.delai_min} aria-describedby={id('battement')} onChange={(e) => setBat({ ...bat, delai_min: Number(e.target.value) || 2 })} /></label>
        </div>
        <p className="field-hint" id={id('battement')}>{tr("Une ligne de test part du manager Wazuh à chaque période et traverse toute la chaîne (integrations/wazuh, section 7). Sans elle au-delà du délai (au moins deux périodes), l'équipe voit un bandeau et le canal d'astreinte est prévenu : des alertes peuvent ne plus arriver.")}</p>
        {c.battement.active && (
          <p className={c.battement.manquant_depuis ? 'banner danger' : 'muted small'} role={c.battement.manquant_depuis ? 'alert' : undefined}>
            {c.battement.manquant_depuis
              ? tr('Chaîne muette : aucun battement depuis {d}.', { d: formatUtc(c.battement.dernier || c.battement.manquant_depuis) })
              : c.battement.dernier ? tr('Dernier battement : {d} ({s}).', { d: formatUtc(c.battement.dernier), s: c.battement.source || '?' }) : tr('Aucun battement reçu pour l’instant.')}
          </p>
        )}

        <h3>{tr('Rapport')}</h3>
        <label className="check"><input type="checkbox" checked={rapport} onChange={(e) => setRapport(e.target.checked)} />{' '}
          {tr("Inclure le délai d'acquittement dans le rapport périodique remis au client")}</label>
        <div><button type="button" className="primary" onClick={save} disabled={!changed}>{tr('Enregistrer')}</button></div>
        <ActionStatus state={status} />

        <h3>{tr('Réversibilité')}</h3>
        <p className="field-hint">{tr("Toutes les données du client dans une archive ZIP (tickets et leur contexte, pièces, notifications, parc, journal d'audit), avec l'empreinte de chaque fichier (PDIS IV.5.2.b). La destruction en fin de prestation se fait ensuite sur le serveur : keryx destroy-client.")}</p>
        <div><button type="button" onClick={() => track(async () => { downloadBlob(await api(`/politique/${encodeURIComponent(c.key)}/export`), `keryx-${c.key}.zip`); return true }, tr('Export téléchargé.'))}>{tr('Exporter toutes les données du client (ZIP)')}</button></div>
      </div>
    </section>
  )
}

export default function Politique() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api('/politique').then(setData).catch((e) => setError(e.message)) }, [])
  const saved = (r) => setData((d) => ({ ...d, items: d.items.map((x) => (x.key === r.key ? { ...x, ...r } : x)) }))
  return (
    <>
      <header className="page-head"><div>
        <h1>{tr('Politique des clients')}</h1>
        <p className="muted">{tr('Règles appliquées aux tickets de chacun de vos clients. Chaque modification est inscrite au journal d’audit.')}</p>
      </div></header>
      {error && <p className="error" role="alert">{error}</p>}
      {data === null && !error && <p className="loading">{tr('Chargement…')}</p>}
      {data?.items.map((c) => <Client key={c.key} c={c} canaux={data.canaux} onSaved={saved} />)}
    </>
  )
}
