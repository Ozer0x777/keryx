import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { Severity } from '../components/Badges.jsx'
import Html from '../components/Html.jsx'
import { formatUtc, STATUS, VERDICTS } from '../labels.js'

// Rapport d'incident imprimable (Imprimer > Enregistrer au format PDF). [PRIS VI.5.3.d, e]
export default function TicketReport() {
  const { ref } = useParams()
  const [t, setT] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api(`/tickets/${encodeURIComponent(ref)}`).then(setT).catch((e) => setError(e.message)) }, [ref])
  if (error) return <p className="error" role="alert">{error}</p>
  if (!t) return <p className="loading">Chargement…</p>
  const s = t.synthese || {}
  return (
    <>
      <div className="row gap noprint" style={{ marginBottom: 12 }}>
        <Link to={`/tickets/${encodeURIComponent(ref)}`}>← Retour au ticket</Link>
        <button type="button" className="primary push" onClick={() => window.print()}>Imprimer / PDF</button>
      </div>
      <article className="report card section" aria-label="Rapport d'incident">
        <h1>Rapport d'incident {t.ref}</h1>
        <p className="muted">{t.title}</p>
        <p className="muted small">{t.client} · {t.tlp} · statut {STATUS[t.status]?.label}</p>
        <dl className="kv">
          <dt>Détecté le</dt><dd>{formatUtc(t.detected_at)}</dd>
          <dt>Règle Wazuh</dt><dd>{t.rule.id} (niveau {t.rule.level}) — {t.rule.description}</dd>
          <dt>Équipement</dt><dd>{t.agent.name} {t.agent.ip || ''}</dd>
          <dt>Criticité initiale</dt><dd><Severity value={t.criticite_initiale} /></dd>
          <dt>Gravité qualifiée</dt><dd><Severity value={t.gravite} /></dd>
          <dt>Verdict</dt><dd>{VERDICTS[t.verdict] || 'À qualifier'}</dd>
          <dt>MITRE ATT&amp;CK</dt><dd>{t.mitre_detail.map((m) => `${m.id}${m.technique ? ` ${m.technique}` : ''}`).join(', ') || '—'}</dd>
          <dt>Occurrences</dt><dd>{t.occurrences}</dd>
        </dl>
        {t.impact && <><h2>Impact constaté</h2><p>{t.impact}</p></>}
        {t.risque && <><h2>Risque induit</h2><p>{t.risque}</p></>}
        <h2>Description</h2><Html html={t.body_html} />
        {s.chronologie && <><h2>Chronologie</h2><Html html={s.chronologie} /></>}
        {s.mode_operatoire && <><h2>Mode opératoire</h2><Html html={s.mode_operatoire} /></>}
        {s.perimetre && <><h2>Périmètre</h2><Html html={s.perimetre} /></>}
        {s.rex_html && <><h2>Retour d'expérience</h2><Html html={s.rex_html} /></>}
        <h2>Registre des actions</h2>
        <table className="grid"><thead><tr><th scope="col">Date</th><th scope="col">Auteur</th><th scope="col">Action</th></tr></thead>
          <tbody>{t.events.map((e, i) => <tr key={i}><td className="mono small">{formatUtc(e.ts)}</td><td>{e.actor}</td><td>{e.action}</td></tr>)}</tbody></table>
        {t.attachments.length > 0 && <>
          <h2>Registre des preuves</h2>
          <table className="grid"><thead><tr><th scope="col">Fichier</th><th scope="col">SHA-256</th><th scope="col">Collecte</th><th scope="col">Méthode</th></tr></thead>
            <tbody>{t.attachments.map((a) => <tr key={a.id}><td>{a.filename}</td><td className="mono small">{a.sha256}</td><td className="mono small">{formatUtc(a.collected_at)}</td><td>{a.method}</td></tr>)}</tbody></table></>}
      </article>
    </>
  )
}
