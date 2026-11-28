import { t as tr } from '../i18n.js'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { Severity } from '../components/Badges.jsx'
import PdfButton from '../components/PdfButton.jsx'
import Html from '../components/Html.jsx'
import { Occurrences } from './RapportAnalyse.jsx'
import { formatUtc, STATUS, VERDICTS } from '../labels.js'

// Rapport d'incident imprimable (Imprimer > Enregistrer au format PDF). [PRIS VI.5.3.d, e]
export default function TicketReport() {
  const { ref } = useParams()
  const [t, setT] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api(`/tickets/${encodeURIComponent(ref)}`, { params: { complet: true } }).then(setT).catch((e) => setError(e.message)) }, [ref])
  if (error) return <p className="error" role="alert">{error}</p>
  if (!t) return <p className="loading">{tr("Chargement…")}</p>
  const s = t.synthese || {}
  return (
    <>
      <div className="row gap noprint" style={{ marginBottom: 12 }}>
        <Link to={`/tickets/${encodeURIComponent(ref)}`}>{tr("← Retour au ticket")}</Link>
        <span className="row gap push"><PdfButton path={`/tickets/${encodeURIComponent(ref)}/rapport.pdf`} filename={`${ref}-rapport.pdf`} primary />
          <button type="button" onClick={() => window.print()}>{tr("Imprimer")}</button></span>
      </div>
      <article className="report card section" aria-label={tr("Rapport d'incident")}>
        <h1>{tr("Rapport d'incident")} {t.ref}</h1>
        <p className="muted">{t.title}</p>
        <p className="muted small">{t.client} · {t.tlp} · {tr('statut {s}', { s: STATUS[t.status]?.label })}</p>
        <dl className="kv">
          <dt>{tr("Détecté le")}</dt><dd>{formatUtc(t.detected_at)}</dd>
          <dt>{tr("Niveau de classification")}</dt><dd>{tr(t.niveau_classification)}</dd>
          <dt>{tr("Règle Wazuh")}</dt><dd>{t.rule.id} ({tr('niveau {level}', { level: t.rule.level })}{t.rule.version ? `, ${tr('version {v}', { v: t.rule.version })}` : ''}) — {t.rule.description}</dd>
          <dt>{tr("Équipement")}</dt><dd>{t.agent.name} {t.agent.ip || ''}</dd>
          <dt>{tr("Collecteur")}</dt><dd>{t.collecteur || '—'}</dd>
          <dt>{tr("Criticité initiale")}</dt><dd><Severity value={t.criticite_initiale} /></dd>
          <dt>{tr("Gravité qualifiée")}</dt><dd><Severity value={t.gravite} /></dd>
          <dt>{tr("Verdict")}</dt><dd>{VERDICTS[t.verdict] || tr('À qualifier')}</dd>
          <dt>MITRE ATT&amp;CK</dt><dd>{t.mitre_detail.map((m) => `${m.id}${m.technique ? ` ${m.technique}` : ''}`).join(', ') || '—'}</dd>
          <dt>{tr("Occurrences")}</dt><dd>{t.occurrences}</dd>
        </dl>
        {t.impact && <><h2>{tr("Impact constaté")}</h2><p>{t.impact}</p></>}
        {t.risque && <><h2>{tr("Risque induit")}</h2><p>{t.risque}</p></>}
        <h2>{tr("Description")}</h2><Html html={t.body_html} />
        {s.chronologie && <><h2>{tr("Chronologie")}</h2><Html html={s.chronologie} /></>}
        {s.mode_operatoire && <><h2>{tr("Mode opératoire")}</h2><Html html={s.mode_operatoire} /></>}
        {s.perimetre && <><h2>{tr("Périmètre")}</h2><Html html={s.perimetre} /></>}
        {s.rex_html && <><h2>{tr("Retour d'expérience")}</h2><Html html={s.rex_html} /></>}
        <h2>{tr("Registre des actions")}</h2>
        <table className="grid"><thead><tr><th scope="col">{tr("Date")}</th><th scope="col">{tr("Auteur")}</th><th scope="col">{tr("Action")}</th></tr></thead>
          <tbody>{t.events.map((e, i) => <tr key={i}><td className="mono small">{formatUtc(e.ts)}</td><td>{e.actor}</td><td>{e.action}</td></tr>)}</tbody></table>
        <Occurrences o={t.occurrences_resume} />
        {t.attachments.length > 0 && <>
          <h2>{tr("Registre des preuves")}</h2>
          <table className="grid"><thead><tr><th scope="col">{tr("Fichier")}</th><th scope="col">{tr("SHA-256")}</th><th scope="col">{tr("Collecte")}</th><th scope="col">{tr("Méthode")}</th></tr></thead>
            <tbody>{t.attachments.map((a) => <tr key={a.id}><td>{a.filename}</td><td className="mono small">{a.sha256}</td><td className="mono small">{formatUtc(a.collected_at)}</td><td>{a.method}</td></tr>)}</tbody></table></>}
      </article>
    </>
  )
}
