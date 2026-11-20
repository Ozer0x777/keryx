import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, downloadBlob } from '../api.js'
import { useAuth } from '../App.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import Crisis from '../components/Crisis.jsx'
import Stamps from '../components/Stamps.jsx'
import RichEditor from '../components/RichEditor.jsx'
import {
  DOMMAGES, formatUtc, IMPORTANCES, LIFECYCLE, MITRE_SOURCE, SCAN, STATUS, TLPS, TRANSITIONS, VERDICTS,
} from '../labels.js'

// Le HTML affiché ici (description, commentaires, synthèse) est assaini côté serveur (nh3, liste blanche).
function Html({ html }) {
  return <div className="rich-content" dangerouslySetInnerHTML={{ __html: html || '' }} />
}

function Section({ title, children, extra }) {
  return (
    <section className="card section" aria-label={title}>
      <header className="section-head"><h2>{title}</h2>{extra}</header>
      <div className="section-body">{children}</div>
    </section>
  )
}

const nowLocal = () => new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)

export default function Ticket() {
  const { ref } = useParams()
  const { me } = useAuth()
  const [t, setT] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const isClient = me.role === 'client'
  const isTeam = me.role === 'analyst' || me.role === 'manager'
  const enc = encodeURIComponent(ref)

  const load = useCallback(async () => {
    try { setT(await api(`/tickets/${enc}`)) } catch (e) { setError(e.message) }
  }, [enc])
  useEffect(() => { load() }, [load])
  const [tpls, setTpls] = useState([])
  useEffect(() => { if (isTeam) api('/templates').then((r) => setTpls(r.items)).catch(() => {}) }, [isTeam])
  const templates = (kind) => tpls.filter((x) => x.kind === kind)

  const run = async (fn, okMessage) => {
    setNotice('')
    try {
      await fn()
      if (okMessage) setNotice(okMessage)
      await load()
      return true
    } catch (e) {
      setNotice(`Erreur : ${e.message}`)
      return false
    }
  }

  if (error) return <p className="error" role="alert">{error}</p>
  if (!t) return <p className="loading">Chargement…</p>
  const open = ['nouveau', 'en_evaluation', 'en_reponse'].includes(t.status)

  // visible : l'image n'est montrée au client que si le contenu qui l'embarque l'est aussi.
  const uploadImage = async (file, visible = false) => {
    const description = window.prompt("Description de l'image (registre de collecte)", "Capture d'écran")
    if (!description) return null
    const form = new FormData()
    form.append('file', file)
    form.append('description', description)
    form.append('collected_at', new Date().toISOString())
    form.append('method', isClient ? 'Capture fournie par le client' : "Capture d'écran par l'analyste")
    form.append('sensitivity', t.tlp)
    form.append('visible_client', visible || isClient ? 'true' : 'false')
    try {
      const a = await api(`/tickets/${enc}/attachments`, { method: 'POST', form })
      await load()
      return `/api/v1/attachments/${a.id}/content`
    } catch (e) {
      setNotice(`Erreur : ${e.message}`)
      return null
    }
  }

  const exportIodef = async () => {
    try {
      const doc = await api(`/tickets/${enc}/iodef`)
      downloadBlob(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' }), `${t.ref}.iodef.json`)
    } catch (e) { setNotice(`Erreur : ${e.message}`) }
  }

  return (
    <>
      <nav className="breadcrumb" aria-label="Fil d'Ariane">
        <Link to="/tickets">{isClient ? 'Mes incidents' : 'Tickets'}</Link> / {t.client} / <span className="mono">{t.ref}</span>
      </nav>
      <header className="ticket-head">
        <div className="grow">
          <h1>{t.title}</h1>
          <div className="row wrap gap">
            <Status value={t.status} />
            <Severity value={t.criticite_initiale} prefix="Criticité initiale : " />
            {t.gravite && <Severity value={t.gravite} prefix="Gravité : " />}
            <Tlp value={t.tlp} />
            <span className="muted small">Détecté {formatUtc(t.detected_at)} · règle Wazuh {t.rule.id} (niveau {t.rule.level}) · {t.occurrences} occurrence(s)</span>
          </div>
        </div>
        {isTeam && (
          <div className="row wrap gap">
            <Link to={`/tickets/${enc}/rapport`} className="btn-link">Rapport imprimable</Link>
            <button type="button" onClick={exportIodef}>Exporter (IODEF JSON)</button>
            {(TRANSITIONS[t.status] || []).map((s) => (
              <button type="button" key={s} className="primary"
                onClick={() => run(() => api(`/tickets/${enc}/status`, { method: 'POST', json: { status: s } }), `Statut : ${STATUS[s].label}.`)}>
                → {STATUS[s].label}
              </button>
            ))}
          </div>
        )}
      </header>
      <p className="live" role="status" aria-live="polite">{notice}</p>
      {t.rex_en_attente && <p className="banner warn">Incident {t.gravite || t.criticite_initiale} clôturé : le retour d'expérience est obligatoire (section Synthèse).</p>}

      {t.crisis && <p className="banner danger" role="status">MODE CRISE actif sur ce ticket : toute décision et toute action sont consignées dans le registre de crise.</p>}
      <div className="ticket-layout">
        <div className="ticket-main">
          {isTeam && <Crisis t={t} enc={enc} isManager={me.role === 'manager'} open={open} onChange={load} />}
          <Description t={t} enc={enc} canEdit={isTeam && open} run={run} onImage={(f) => uploadImage(f, true)} />
          {isTeam && <AlertBlock t={t} />}
          <Attachments t={t} enc={enc} me={me} run={run} setNotice={setNotice} />
          {isTeam && <Synthese t={t} enc={enc} run={run} onImage={(f) => uploadImage(f, false)} templates={templates('synthese')} />}
          <Events t={t} />
          <Comments t={t} enc={enc} isClient={isClient} run={run} onImage={uploadImage} templates={templates('commentaire')} />
        </div>
        {isTeam && (
          <aside className="ticket-aside" aria-label="Pilotage du ticket">
            <Qualification t={t} enc={enc} run={run} open={open} />
            <Mitre t={t} enc={enc} run={run} open={open} />
            <Assignment t={t} enc={enc} run={run} open={open} />
            <Links t={t} enc={enc} run={run} open={open} />
            <Details t={t} />
          </aside>
        )}
      </div>
    </>
  )
}

function BodyHistory({ enc, current }) {
  const [h, setH] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api(`/tickets/${enc}/body-history`).then(setH).catch((e) => setError(e.message)) }, [enc, current])
  if (error) return <p className="error" role="alert">{error}</p>
  if (!h) return <p className="muted small">Chargement…</p>
  if (h.versions.length === 0) return <p className="muted small">Aucune modification depuis la création du ticket.</p>
  return (
    <ol className="versions" aria-label="Versions de la description">
      {[...h.versions].reverse().map((v, i) => (
        <li key={v.ts + i}>
          <details>
            <summary>Avant la modification du <span className="mono">{formatUtc(v.ts)}</span> par <strong>{v.actor}</strong>{v.truncated ? ' (aperçu tronqué)' : ''}</summary>
            <Html html={v.html} />
            {v.truncated && <p className="muted small">Version complète de {v.length} caractères ; empreinte SHA-256 <span className="mono">{v.sha256}</span>.</p>}
          </details>
        </li>
      ))}
    </ol>
  )
}

function Description({ t, enc, canEdit, run, onImage }) {
  const [editing, setEditing] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [html, setHtml] = useState(t.body_html)
  const isTeam = t.raw_alerts !== undefined
  return (
    <Section title="Description" extra={<div className="row gap">
      {isTeam && <button type="button" aria-expanded={showHistory} onClick={() => setShowHistory(!showHistory)}>{showHistory ? "Masquer l'historique" : 'Historique'}</button>}
      {canEdit && !editing && <button type="button" onClick={() => { setHtml(t.body_html); setEditing(true) }}>Modifier</button>}</div>}>
      {showHistory && <BodyHistory enc={enc} current={t.body_html} />}
      {editing ? (
        <>
          <RichEditor value={html} onChange={setHtml} label="Description du ticket" onImage={onImage} minHeight={200} />
          <div className="row gap end">
            <button type="button" onClick={() => setEditing(false)}>Annuler</button>
            <button type="button" className="primary" onClick={async () => {
              if (await run(() => api(`/tickets/${enc}/body`, { method: 'PUT', json: { body_html: html } }), 'Description enregistrée (version précédente conservée).')) setEditing(false)
            }}>Enregistrer</button>
          </div>
        </>
      ) : <Html html={t.body_html} />}
    </Section>
  )
}

function AlertBlock({ t }) {
  return (
    <Section title="Alerte Wazuh" extra={<span className="muted small">{t.raw_alerts} alerte(s) brute(s) conservée(s) avec empreinte SHA-256</span>}>
      <dl className="kv">
        <dt>Règle</dt><dd className="mono">{t.rule.id} · niveau {t.rule.level}</dd>
        <dt>Description</dt><dd>{t.rule.description}</dd>
        <dt>Groupes</dt><dd className="mono">{t.rule.groups.join(', ') || '—'}</dd>
        <dt>Agent</dt><dd className="mono">{[t.agent.id, t.agent.name, t.agent.ip].filter(Boolean).join(' · ') || '—'}</dd>
        <dt>Classification</dt><dd className="mono small">{t.classification.join(', ') || '—'}</dd>
      </dl>
    </Section>
  )
}

function Attachments({ t, enc, me, run, setNotice }) {
  const isClient = me.role === 'client'
  const isTeam = !isClient
  const [form, setForm] = useState(null)
  const [ext, setExt] = useState(null)

  const download = async (a) => {
    let params = {}
    if (a.scan_status === 'quarantaine') {
      if (!window.confirm(`${a.filename} a été détecté comme malveillant. Il sera fourni dans une archive ZIP chiffrée (mot de passe : voir le guide d\'exploitation). Le télécharger quand même, pour analyse ?`)) return
      params.confirmer_malveillant = 'true'
    }
    if (a.kind === 'fichier' || a.scan_status === 'quarantaine') {
      const motif = window.prompt('Motif du téléchargement (chaîne de possession)')
      if (!motif || motif.length < 3) return
      params.motif = motif
    }
    try {
      const blob = await api(`/attachments/${a.id}/content`, { params })
      downloadBlob(blob, a.filename + (a.scan_status === 'quarantaine' ? '.quarantaine.zip' : ''))
    } catch (e) { setNotice(`Erreur : ${e.message}`) }
  }

  const lifecycle = (a, value) => {
    const reason = window.prompt(value === 'detruit' ? 'Motif de la destruction (irréversible)' : 'Motif de la restitution')
    if (!reason || reason.length < 3) return
    run(() => api(`/attachments/${a.id}/lifecycle`, { method: 'POST', json: { lifecycle: value, reason } }), `Pièce ${LIFECYCLE[value].toLowerCase()}e.`)
  }

  const submit = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    fd.set('collected_at', new Date(fd.get('collected_at')).toISOString())
    if (!isClient) fd.set('visible_client', fd.get('visible_client') ? 'true' : 'false')
    if (await run(() => api(`/tickets/${enc}/attachments`, { method: 'POST', form: fd }), 'Pièce déposée.')) setForm(null)
  }

  const submitExt = async (e) => {
    e.preventDefault()
    const fd = Object.fromEntries(new FormData(e.target))
    const json = { ...fd, collected_at: new Date(fd.collected_at).toISOString(), size: Number(fd.size || 0), sha256: fd.sha256.toLowerCase() }
    if (await run(() => api(`/tickets/${enc}/preuves-externes`, { method: 'POST', json }), 'Preuve externe déclarée.')) setExt(null)
  }

  return (
    <Section title={isClient ? 'Éléments déposés' : 'Registre des preuves'} extra={
      <div className="row gap">
        {isTeam && <button type="button" onClick={() => { setExt(true); setForm(null) }}>Déclarer une preuve externe</button>}
        <button type="button" className="dark" onClick={() => { setForm(true); setExt(null) }}>Déposer un fichier ({t.attachment_max_mb ?? 20} Mo max)</button>
      </div>}>
      {form && (
        <form className="subform" onSubmit={submit}>
          <label>Fichier (archive ZIP, PNG, JPEG ou WebP)<input type="file" name="file" accept=".zip,image/png,image/jpeg,image/webp" required /></label>
          <label>Description (obligatoire)<input name="description" minLength={3} required /></label>
          <div className="grid2">
            <label>Date et heure de collecte<input type="datetime-local" name="collected_at" defaultValue={nowLocal()} required /></label>
            <label>Sensibilité<select name="sensitivity" defaultValue={t.tlp}>{TLPS.map((x) => <option key={x}>{x}</option>)}</select></label>
          </div>
          <label>Méthode de collecte (obligatoire)<input name="method" minLength={3} placeholder="ex. export du journal du pare-feu" required /></label>
          {!isClient && <label className="check"><input type="checkbox" name="visible_client" value="true" /> Visible par le client</label>}
          <p className="muted small">L'archive n'est jamais décompressée par Keryx. Analyse antivirus automatique quand ClamAV est configuré.</p>
          <div className="row gap end"><button type="button" onClick={() => setForm(null)}>Annuler</button><button className="primary">Déposer</button></div>
        </form>
      )}
      {ext && (
        <form className="subform" onSubmit={submitExt}>
          <p className="muted small">Pour une preuve de plus de {t.attachment_max_mb ?? 20} Mo (image disque, dump mémoire, pcap) conservée hors de Keryx, sur un support hors ligne.</p>
          <label>Nom<input name="filename" required /></label>
          <label>Description<input name="description" minLength={3} required /></label>
          <div className="grid2">
            <label>Date et heure de collecte<input type="datetime-local" name="collected_at" defaultValue={nowLocal()} required /></label>
            <label>Taille (octets)<input type="number" name="size" min="0" /></label>
          </div>
          <label>Méthode de collecte<input name="method" minLength={3} required /></label>
          <label>Empreinte SHA-256<input name="sha256" pattern="[0-9a-fA-F]{64}" className="mono" required /></label>
          <label>Lieu de conservation<input name="location" minLength={3} placeholder="ex. coffre hors ligne n°2" required /></label>
          <label>Sensibilité<select name="sensitivity" defaultValue={t.tlp}>{TLPS.map((x) => <option key={x}>{x}</option>)}</select></label>
          <div className="row gap end"><button type="button" onClick={() => setExt(null)}>Annuler</button><button className="primary">Déclarer</button></div>
        </form>
      )}
      {t.attachments.length === 0 ? <p className="muted">Aucune pièce.</p> : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th scope="col">Élément</th><th scope="col">Collecte · méthode</th><th scope="col">SHA-256</th><th scope="col">Antivirus</th><th scope="col">Sort</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {t.attachments.map((a) => (
                <tr key={a.id}>
                  <td><strong>{a.filename}</strong><div className="muted small">{a.description} · {a.sensitivity}{a.location ? ` · ${a.location}` : ''}</div></td>
                  <td className="small">{formatUtc(a.collected_at)}<div className="muted">{a.method}</div></td>
                  <td className="small"><span className="mono" title={a.sha256}>{a.sha256.slice(0, 12)}…{a.sha256.slice(-6)}</span>
                    {a.lifecycle === 'conserve' && <Stamps attachmentId={a.id} canStamp={isTeam && !!me.features?.timestamping} />}</td>
                  <td><span className={`pill ${a.scan_status === 'quarantaine' ? 'danger' : a.scan_status === 'sain' ? 'ok' : ''}`}>{SCAN[a.scan_status]}</span></td>
                  <td>{a.kind === 'preuve_externe' ? 'Hors Keryx' : LIFECYCLE[a.lifecycle]}</td>
                  <td className="row gap">
                    {a.kind !== 'preuve_externe' && a.lifecycle === 'conserve' && !(isClient && a.scan_status === 'quarantaine') &&
                      <button type="button" className="small-btn" onClick={() => download(a)}>Télécharger</button>}
                    {isTeam && a.lifecycle === 'conserve' && <button type="button" className="small-btn" onClick={() => lifecycle(a, 'restitue')}>Restituer</button>}
                    {me.role === 'manager' && a.lifecycle === 'conserve' && <button type="button" className="small-btn danger" onClick={() => lifecycle(a, 'detruit')}>Détruire</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">Chaque dépôt, téléchargement, restitution ou destruction est inscrit dans la chaîne de possession.</p>
    </Section>
  )
}

function Synthese({ t, enc, run, onImage, templates }) {
  const s = t.synthese || {}
  const [v, setV] = useState({
    compromission_initiale: s.compromission_initiale ? s.compromission_initiale.slice(0, 16) : '',
    chronologie: s.chronologie || '', mode_operatoire: s.mode_operatoire || '', perimetre: s.perimetre || '', rex_html: s.rex_html || '',
  })
  const editable = !['faux_positif', 'retour_experience'].includes(t.status)
  const save = () => run(() => api(`/tickets/${enc}/synthese`, {
    method: 'PUT',
    json: { ...v, compromission_initiale: v.compromission_initiale ? new Date(v.compromission_initiale + 'Z').toISOString() : null },
  }), 'Synthèse enregistrée.')
  if (!editable) {
    return (
      <Section title="Synthèse de l'incident et retour d'expérience">
        <h3>Chronologie</h3><Html html={s.chronologie} />
        <h3>Mode opératoire</h3><Html html={s.mode_operatoire} />
        <h3>Périmètre</h3><Html html={s.perimetre} />
        <h3>Retour d'expérience</h3><Html html={s.rex_html} />
      </Section>
    )
  }
  return (
    <Section title="Synthèse de l'incident et retour d'expérience" extra={<span className="muted small">PRIS VI.5.3.e · ISO 27035</span>}>
      <label>Date de compromission initiale (UTC)
        <input type="datetime-local" value={v.compromission_initiale} onChange={(e) => setV({ ...v, compromission_initiale: e.target.value })} />
      </label>
      <h3>Chronologie</h3>
      <RichEditor value={v.chronologie} onChange={(x) => setV({ ...v, chronologie: x })} label="Chronologie" templates={templates} minHeight={80} />
      <h3>Mode opératoire</h3>
      <RichEditor value={v.mode_operatoire} onChange={(x) => setV({ ...v, mode_operatoire: x })} label="Mode opératoire" templates={templates} minHeight={80} />
      <h3>Périmètre</h3>
      <RichEditor value={v.perimetre} onChange={(x) => setV({ ...v, perimetre: x })} label="Périmètre" templates={templates} minHeight={80} />
      <h3>Retour d'expérience {t.rex_required && <span className="pill warn">obligatoire</span>}</h3>
      <RichEditor value={v.rex_html} onChange={(x) => setV({ ...v, rex_html: x })} label="Retour d'expérience" templates={templates} onImage={onImage} minHeight={80} />
      <div className="row end"><button type="button" className="primary" onClick={save}>Enregistrer la synthèse</button></div>
    </Section>
  )
}

function fmtDetail(v) {
  if (v === null || v === undefined || v === '') return '—'
  if (Array.isArray(v)) return v.map(fmtDetail).join(', ')
  if (typeof v === 'object') return Object.entries(v).map(([k, x]) => `${k} : ${fmtDetail(x)}`).join(', ')
  return String(v)
}

function Events({ t }) {
  return (
    <Section title="Registre des actions">
      <ol className="timeline">
        {t.events.map((e, i) => (
          <li key={i}>
            <span className="mono small muted">{formatUtc(e.ts)}</span>
            <span className="strong">{e.actor}</span>
            <span>{e.action}{e.details && Object.keys(e.details).length > 0 && e.action !== 'description'
              ? ` — ${Object.entries(e.details).map(([k, v]) => `${k} : ${fmtDetail(v)}`).join(' · ')}` : ''}</span>
          </li>
        ))}
      </ol>
    </Section>
  )
}

function Comments({ t, enc, isClient, run, onImage, templates }) {
  const [html, setHtml] = useState('')
  const [visible, setVisible] = useState(isClient)
  const post = async () => {
    if (!html.trim()) return
    if (await run(() => api(`/tickets/${enc}/comments`, { method: 'POST', json: { body_html: html, visible_client: visible } }), 'Commentaire publié.')) setHtml('')
  }
  const saveTemplate = async () => {
    const name = window.prompt('Nom du modèle (propre à ce client)')
    if (!name) return
    run(() => api('/templates', { method: 'POST', json: { kind: 'commentaire', name, body_html: html, client: t.client_key } }), 'Modèle enregistré.')
  }
  return (
    <Section title={isClient ? 'Échanges avec le SOC' : 'Commentaires'}>
      {t.comments.length === 0 && <p className="muted">Aucun commentaire.</p>}
      {t.comments.map((c, i) => (
        <div key={i} className={`comment ${c.visible_client ? 'public' : 'internal'}`}>
          <div className="comment-head">{c.visible_client ? (isClient ? '' : 'VISIBLE CLIENT · ') : 'INTERNE · '}{c.author} · {formatUtc(c.created_at)}</div>
          <Html html={c.body_html} />
        </div>
      ))}
      <h3>{isClient ? 'Votre réponse' : 'Nouveau commentaire'}</h3>
      <RichEditor value={html} onChange={setHtml} label="Nouveau commentaire" templates={templates} onImage={(f) => onImage(f, isClient || visible)} />
      <div className="row gap between">
        {!isClient ? <label className="check"><input type="checkbox" checked={visible} onChange={(e) => setVisible(e.target.checked)} /> Visible par le client</label> : <span />}
        <div className="row gap">
          {!isClient && <button type="button" onClick={saveTemplate} disabled={!html.trim()}>Enregistrer comme modèle</button>}
          <button type="button" className="dark" onClick={post}>Publier</button>
        </div>
      </div>
      {!isClient && <p className="muted small">Mentionnez un collègue avec @identifiant : il recevra une notification.</p>}
    </Section>
  )
}

function Qualification({ t, enc, run, open }) {
  const [v, setV] = useState({ verdict: t.verdict || '', dommages: t.dommages || '', importance: t.importance, impact: t.impact || '', risque: t.risque || '', tlp: t.tlp })
  const verdictLocked = !['nouveau', 'en_evaluation'].includes(t.status)
  const save = () => {
    const json = { importance: v.importance, impact: v.impact, risque: v.risque, tlp: v.tlp }
    if (v.verdict && !verdictLocked) json.verdict = v.verdict
    if (v.dommages) json.dommages = v.dommages
    run(() => api(`/tickets/${enc}/qualification`, { method: 'POST', json }), 'Qualification enregistrée.')
  }
  return (
    <section className="card section" aria-label="Qualification">
      <h2>Qualification</h2>
      <label>Verdict
        <select value={v.verdict} disabled={!open || verdictLocked} onChange={(e) => setV({ ...v, verdict: e.target.value })}>
          <option value="">À qualifier</option>
          {Object.entries(VERDICTS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
      </label>
      {verdictLocked && open && <p className="muted small">Verdict figé hors de la phase d'évaluation.</p>}
      <div className="grid2">
        <label>Dommages
          <select value={v.dommages} disabled={!open} onChange={(e) => setV({ ...v, dommages: e.target.value })}>
            <option value="">—</option>
            {Object.entries(DOMMAGES).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </label>
        <label>Importance
          <select value={v.importance} disabled={!open} onChange={(e) => setV({ ...v, importance: e.target.value })}>
            {Object.entries(IMPORTANCES).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </label>
      </div>
      {t.severity_hint && open && (
        <p className="muted small" data-testid="severity-hint">Selon l'importance « {IMPORTANCES[v.importance]} » de l'équipement : dommages limités → <strong>{t.severity_hint.limites}</strong>, significatifs → <strong>{t.severity_hint.significatifs}</strong>, graves → <strong>{t.severity_hint.graves}</strong> (grille du client). La gravité est fixée par votre qualification.</p>
      )}
      <div className="row between gravity"><span className="muted">Gravité qualifiée</span><Severity value={t.gravite} /></div>
      <label>Impact constaté<textarea rows="2" value={v.impact} disabled={!open} onChange={(e) => setV({ ...v, impact: e.target.value })} /></label>
      <label>Risque induit<textarea rows="2" value={v.risque} disabled={!open} onChange={(e) => setV({ ...v, risque: e.target.value })} /></label>
      <label>Marquage<select value={v.tlp} disabled={!open} onChange={(e) => setV({ ...v, tlp: e.target.value })}>{TLPS.map((x) => <option key={x}>{x}</option>)}</select></label>
      {open && <button type="button" className="primary wide" onClick={save}>Enregistrer</button>}
    </section>
  )
}

function Mitre({ t, enc, run, open }) {
  const [text, setText] = useState(t.mitre.join(', '))
  const [q, setQ] = useState('')
  const [found, setFound] = useState([])
  useEffect(() => {
    if (q.trim().length < 2) { setFound([]); return undefined }
    const h = setTimeout(() => api('/mitre/techniques', { params: { q } }).then((r) => setFound(r.items)).catch(() => setFound([])), 250)
    return () => clearTimeout(h)
  }, [q])
  return (
    <section className="card section" aria-label="MITRE ATT&CK">
      <h2>MITRE ATT&amp;CK</h2>
      {t.mitre_detail.length === 0 && <p className="muted">À compléter.</p>}
      {t.mitre_detail.map((m) => (
        <div key={m.id} className="mitre">
          <a className="mono chip" href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer">{m.id}</a>
          <span>{m.technique}</span>
          {m.tactics?.length > 0 && <span className="muted small">{m.tactics.join(', ')}</span>}
        </div>
      ))}
      <p className="muted small">Source : <strong>{MITRE_SOURCE[t.mitre_source]}</strong></p>
      {open && (
        <>
          <label>Rechercher une technique (nom ou identifiant)<input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="ex. brute force" /></label>
          {found.length > 0 && (
            <ul className="found">{found.map((f) => (
              <li key={f.id}><button type="button" className="link" onClick={() => { setText((x) => [...new Set([...x.split(/[\s,;]+/).filter(Boolean), f.id])].join(', ')); setQ('') }}>
                <span className="mono">{f.id}</span> {f.name}</button></li>))}</ul>
          )}
          <label>Techniques (ex. T1110, T1543.003)<input className="mono" value={text} onChange={(e) => setText(e.target.value)} /></label>
          <button type="button" onClick={() => run(() => api(`/tickets/${enc}/mitre`, {
            method: 'POST', json: { techniques: text.split(/[\s,;]+/).filter(Boolean).map((x) => x.toUpperCase()) },
          }), 'MITRE corrigé (tracé).')}>Corriger (tracé)</button>
        </>
      )}
    </section>
  )
}

function Assignment({ t, enc, run, open }) {
  const [people, setPeople] = useState([])
  useEffect(() => { api(`/tickets/${enc}/assignables`).then((r) => setPeople(r.items)).catch(() => {}) }, [enc])
  return (
    <section className="card section" aria-label="Affectation">
      <h2>Affectation</h2>
      <label>Assigné à
        <select disabled={!open} value={people.find((p) => p.display_name === t.assignee)?.username || ''}
          onChange={(e) => run(() => api(`/tickets/${enc}/assign`, { method: 'POST', json: { username: e.target.value || null } }), 'Affectation enregistrée.')}>
          <option value="">Personne</option>
          {people.map((p) => <option key={p.username} value={p.username}>{p.display_name}</option>)}
        </select>
      </label>
    </section>
  )
}

const LINK_LABEL = { parent: 'Parent', enfant: 'Enfant', lie: 'Lié', doublon: 'Doublon de', 'doublon_de_celui-ci': 'Doublon de ce ticket' }

function Links({ t, enc, run, open }) {
  const [items, setItems] = useState([])
  const [kind, setKind] = useState('lie')
  const [ref, setRef] = useState('')
  const [err, setErr] = useState('')
  const load = useCallback(() => api(`/tickets/${enc}/links`).then((r) => setItems(r.items)).catch(() => {}), [enc])
  useEffect(() => { load() }, [load, t.status])
  const add = async (e) => {
    e.preventDefault(); setErr('')
    try { setItems((await api(`/tickets/${enc}/links`, { method: 'POST', json: { ref: ref.trim().toUpperCase(), kind } })).items); setRef('') } catch (x) { setErr(x.message) }
  }
  const drop = async (id) => { try { setItems((await api(`/tickets/${enc}/links/${id}`, { method: 'DELETE' })).items) } catch (x) { setErr(x.message) } }
  const merge = async () => {
    const into = window.prompt('Référence du ticket à conserver (ex. ACME-1). Ce ticket sera clos comme doublon.')
    if (!into) return
    const reason = window.prompt('Motif de la fusion') || ''
    run(() => api(`/tickets/${enc}/merge`, { method: 'POST', json: { into: into.trim().toUpperCase(), reason } }), 'Ticket fusionné.')
  }
  return (
    <section className="card section" aria-label="Tickets liés">
      <h2>Tickets liés</h2>
      {items.length === 0 && <p className="muted small">Aucun lien.</p>}
      <ul className="linklist">
        {items.map((l) => (
          <li key={l.id}><span className="muted small">{LINK_LABEL[l.kind] || l.kind}</span>{' '}
            <Link to={`/tickets/${encodeURIComponent(l.ref)}`} className="mono">{l.ref}</Link>
            <button type="button" className="x" aria-label={`Supprimer le lien avec ${l.ref}`} onClick={() => drop(l.id)}>×</button></li>
        ))}
      </ul>
      {err && <p className="error" role="alert">{err}</p>}
      <form onSubmit={add} className="row gap wrap">
        <label className="grow">Référence<input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="ACME-2" required /></label>
        <label>Type<select value={kind} onChange={(e) => setKind(e.target.value)}><option value="lie">Lié</option><option value="parent">Parent</option><option value="doublon">Doublon</option></select></label>
        <button>Lier</button>
      </form>
      {open && <button type="button" className="small-btn danger" onClick={merge}>Fusionner dans un autre ticket…</button>}
    </section>
  )
}

function Details({ t }) {
  return (
    <section className="card section" aria-label="Détails">
      <h2>Détails</h2>
      <dl className="kv">
        <dt>Client</dt><dd>{t.client}</dd>
        {t.due_qualification && <><dt>Qualifier avant</dt><dd className="mono small">{formatUtc(t.due_qualification)}</dd></>}
        {t.due_resolution && <><dt>Résoudre avant</dt><dd className="mono small">{formatUtc(t.due_resolution)}</dd></>}
        {t.overdue && <><dt>Échéance</dt><dd><span className="pill danger">Dépassée</span></dd></>}
        <dt>Dernière occurrence</dt><dd className="mono small">{formatUtc(t.last_seen_at)}</dd>
        <dt>REX</dt><dd>{t.rex_required ? 'Obligatoire' : 'Non requis'}</dd>
      </dl>
    </section>
  )
}
