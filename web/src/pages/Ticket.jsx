import { t as tr } from '../i18n.js'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, downloadBlob } from '../api.js'
import { useAuth } from '../App.jsx'
import { tlpAuMoins, tlpSous } from '../tlp.js'
import { ActionStatus, useActionStatus } from '../components/ActionStatus.jsx'
import { Severity, Status, Tlp } from '../components/Badges.jsx'
import { useConfirm } from '../components/Confirm.jsx'
import Crisis from '../components/Crisis.jsx'
import IsiPanel from '../components/IsiPanel.jsx'
import Section, { OPEN_BY_STATUS, OPEN_FOR_CLIENT, PhaseContext } from '../components/Section.jsx'
import Stamps from '../components/Stamps.jsx'
import { TabBar, TabPanel } from '../components/Tabs.jsx'
import WazuhContext from '../components/WazuhContext.jsx'
import { useVirusTotal, VirusTotalPanel, VtPieceButton, VtPieceState } from '../components/VirusTotal.jsx'
import RichEditor from '../components/RichEditor.jsx'
import {
  draftKey, readDraft, UnsavedBadge, UnsavedProvider, UnsavedSummary, useLeaveGuard, useUnsaved,
  useUnsavedRegistry, writeDraft,
} from '../components/Unsaved.jsx'
import { isoToUtcInput, untilUtc, utcClock, utcInputNow, utcInputToIso } from '../dates.js'
import { queuePath } from '../queue.js'
import { confirmTransition, needsConfirm } from '../transitions.jsx'
import {
  DOMMAGES, formatUtc, IMPORTANCES, LIFECYCLE, MITRE_SOURCE, SCAN, STATUS, TLPS, TRANSITIONS, VERDICTS,
} from '../labels.js'

// Le HTML affiché ici (description, commentaires, synthèse) est assaini côté serveur (nh3, liste blanche).
function Html({ html }) {
  return <div className="rich-content" dangerouslySetInnerHTML={{ __html: html || '' }} />
}

// Texte visible d'un HTML assaini. Analyse inerte : le document produit n'exécute ni ne charge rien.
const textOf = (html) => (new DOMParser().parseFromString(html || '', 'text/html').body.textContent || '').replace(/\s+/g, ' ')
// La description générée à l'ingestion reprend la règle, sa description et l'agent de l'alerte : tant qu'elle les
// contient encore, le panneau « Alerte Wazuh » ferait doublon et seules ses données propres sont montrées.
function alertInDescription(t) {
  const text = textOf(t.body_html)
  const has = (v) => { const x = String(v ?? '').replace(/\s+/g, ' ').trim(); return !x || text.includes(x) }
  return has(t.rule.id) && has(t.rule.description) && has(t.agent.name || t.agent.id)
}

// Étape suivante normale du cycle de vie : c'est le seul bouton primaire de l'en-tête, les autres sont secondaires.
// Onglets de la fiche pour l'équipe (ADR-0026). `zones` : les zones de saisie (components/Unsaved.jsx) qui s'y trouvent.
const TABS = [
  { id: 'general', label: 'Vue générale', zones: ['description', 'qualification', 'lien', 'crise'] },
  { id: 'investigation', label: 'Investigation', zones: ['mitre', 'isi'] },
  { id: 'preuves', label: 'Preuves', zones: ['piece', 'preuve-externe', 'virustotal'] },
  { id: 'communication', label: 'Communication', zones: ['commentaire'] },
  { id: 'rex', label: 'REX', zones: ['synthese'] },
]
const TAB_IDS = TABS.map((x) => x.id)

const MAIN_NEXT = { nouveau: 'en_evaluation', en_evaluation: 'en_reponse', en_reponse: 'cloture', cloture: 'retour_experience' }

// Écart d'horloge (ADR-0028) : « détecté » vient du manager Wazuh, « reçu » de Keryx. Reçu AVANT d'être détecté :
// l'horloge du manager avance. Reçu longtemps après : file d'attente ou coupure entre Wazuh et Keryx.
const CLOCK_AHEAD_S = 60
const LATE_S = 15 * 60
function ClockNote({ delay }) {
  if (delay == null) return null
  const min = Math.round(Math.abs(delay) / 60)
  if (delay < -CLOCK_AHEAD_S) {
    return <span className="pill warn" title={tr("Date de détection fournie par Wazuh, date de réception par Keryx : comparer les horloges (NTP).")}>
      {tr("Horloge du manager Wazuh en avance d'environ {n} min sur Keryx", { n: Math.max(min, 1) })}</span>
  }
  if (delay > LATE_S) return <span className="pill">{tr('Reçu {n} min après la détection', { n: min })}</span>
  return null
}

// Échéance de l'en-tête : la date (UTC) et le temps restant ou dépassé, recalculé chaque minute.
function Deadline({ label, iso }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => { const id = setInterval(() => setNow(Date.now()), 60000); return () => clearInterval(id) }, [])
  const d = untilUtc(iso, now)
  const span = d.days ? tr('{d} j {h} h', { d: d.days, h: d.hours }) : d.hours ? tr('{h} h {m} min', { h: d.hours, m: String(d.minutes).padStart(2, '0') }) : tr('{m} min', { m: d.minutes })
  return (
    <div className={d.late ? 'late' : ''}>
      <dt>{label}</dt>
      <dd><span className="mono">{formatUtc(iso)}</span>{' '}
        {d.late ? <span className="pill danger">{tr('Dépassée depuis {d}', { d: span })}</span> : <span className="muted">{tr('dans {d}', { d: span })}</span>}</dd>
    </div>
  )
}

export default function Ticket() {
  const { ref } = useParams()
  const { me } = useAuth()
  const [t, setT] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [headStatus, trackHead] = useActionStatus()
  const [ask, dialog] = useConfirm()
  const isClient = me.role === 'client'
  const isTeam = me.role === 'analyst' || me.role === 'manager'
  const enc = encodeURIComponent(ref)

  const load = useCallback(async () => {
    try { setT(await api(`/tickets/${enc}`)) } catch (e) { setError(e.message) }
  }, [enc])
  useEffect(() => { load() }, [load])
  // Recherche d'empreinte sur VirusTotal (ADR-0022) : null pour le client, pour l'Admin, et quand l'instance l'a coupée.
  const vt = useVirusTotal(isTeam && !!me.features?.virustotal, enc, { announce: setNotice, reload: load })
  const [tpls, setTpls] = useState([])
  useEffect(() => { if (isTeam) api('/templates').then((r) => setTpls(r.items)).catch(() => {}) }, [isTeam])
  const templates = (kind) => tpls.filter((x) => x.kind === kind)

  // Exécute une action sur le ticket, annonce son succès dans la zone live (lecteurs d'écran) et recharge la fiche.
  // Un échec est levé à l'appelant : chaque section l'affiche à côté de son bouton (useActionStatus) ou dans son
  // dialogue, jamais dans un bandeau éloigné du déclencheur.
  const run = async (fn, okMessage) => {
    setNotice('')
    const out = await fn()
    if (okMessage) setNotice(okMessage)
    await load()
    return out
  }

  // Onglet courant : dans l'URL (?onglet=…), pour qu'un rechargement ou un lien retrouve le même onglet.
  const [params, setParams] = useSearchParams()
  const tab = TAB_IDS.includes(params.get('onglet')) ? params.get('onglet') : 'general'
  const selectTab = useCallback((id) => {
    setParams((p) => { const n = new URLSearchParams(p); if (id === 'general') n.delete('onglet'); else n.set('onglet', id); return n }, { replace: true })
    if (window.scrollY > 0) window.scrollTo({ top: 0 })   // le nouvel onglet se lit depuis son début
  }, [setParams])

  // Saisies non enregistrées : indicateur de l'en-tête et garde-fou de sortie (ADR-0024).
  const unsaved = useUnsavedRegistry()
  useLeaveGuard(unsaved.labels, ask)

  const status = t?.status
  const phase = useMemo(() => ({ status, open: isClient ? OPEN_FOR_CLIENT : OPEN_BY_STATUS[status] || null }), [status, isClient])
  const alertMerged = useMemo(() => (t ? alertInDescription(t) : false), [t])

  if (error) return <p className="error" role="alert">{error}</p>
  if (!t) return <p className="loading">{tr("Chargement…")}</p>
  const open = ['nouveau', 'en_evaluation', 'en_reponse'].includes(t.status)

  // Image insérée depuis l'éditeur : déposée sans visibilité client (embedded). Le serveur la rend visible au moment où
  // un contenu visible par le client (commentaire visible, description) qui la référence est enregistré.
  const uploadImage = async (file) => {
    const r = await ask({
      title: tr("Insérer l'image « {name} » et l'inscrire au registre des preuves", { name: file.name }),
      body: <p>{tr("L'image est déposée comme pièce du ticket : sa description figure dans le registre de collecte.")}</p>,
      fields: [{ name: 'description', label: tr("Description de l'image (registre de collecte)"), initial: tr("Capture d'écran"), minLength: 3, maxLength: 500 }],
      confirm: tr("Insérer l'image"),
      action: ({ description }) => {
        const form = new FormData()
        form.append('file', file)
        form.append('description', description)
        form.append('collected_at', new Date().toISOString())
        form.append('method', isClient ? tr('Capture fournie par le client') : tr("Capture d'écran par l'analyste"))
        form.append('sensitivity', tlpAuMoins(t.tlp, t.tlp_plancher))
        form.append('embedded', 'true')
        return api(`/tickets/${enc}/attachments`, { method: 'POST', form })
      },
    })
    if (!r) return null
    await load()
    return `/api/v1/attachments/${r.result.id}/content`
  }

  const exportIodef = () => trackHead(async () => {
    const doc = await api(`/tickets/${enc}/iodef`)
    downloadBlob(new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' }), `${t.ref}.iodef.json`)
  }, tr('Export IODEF téléchargé.'))

  const setStatus = (s) => () => run(() => api(`/tickets/${enc}/status`, { method: 'POST', json: { status: s } }), tr('Statut : {s}.', { s: STATUS[s].label }))
  const transition = async (s) => {
    const msg = tr('Statut : {s}.', { s: STATUS[s].label })
    if (!needsConfirm(s)) { trackHead(setStatus(s), msg); return }
    const done = await confirmTransition(ask, {
      ref: t.ref, client: t.client, target: s,
      send: (reason) => run(() => api(`/tickets/${enc}/status`, { method: 'POST', json: reason ? { status: s, reason } : { status: s } }), msg),
    })
    if (done) trackHead(async () => {}, msg)
  }


  return (
    <>
      <nav className="breadcrumb" aria-label={tr("Fil d'Ariane")}>
        {/* Retour à la file telle qu'on l'a quittée : filtres, tri et vue (voir queue.js). */}
        <Link to={queuePath()}>{isClient ? tr('Mes incidents') : tr('Tickets')}</Link> / {t.client} / <span className="mono">{t.ref}</span>
      </nav>
      <header className="ticket-head">
        <div className="grow">
          <h1>{t.title}</h1>
          <div className="row wrap gap">
            <Status value={t.status} />
            <Severity value={t.criticite_initiale} prefix={tr("Criticité initiale : ")} />
            {t.gravite && <Severity value={t.gravite} prefix={tr("Gravité : ")} />}
            <Tlp value={t.tlp} />
            <span className="muted small">{tr('Détecté {when} · règle Wazuh {rule} (niveau {level}) · {n} occurrence(s)', { when: formatUtc(t.detected_at), rule: t.rule.id, level: t.rule.level, n: t.occurrences })}</span>
            <ClockNote delay={t.reception_delay_s} />
          </div>
        </div>
        {isTeam && (
          <div className="row wrap gap ticket-actions">
            <Link to={`/tickets/${enc}/rapport`} className="btn-link">{tr("Rapport imprimable")}</Link>
            {/* Lien calculé par le serveur pour l'équipe seulement (absent pour le client) ; HTTPS exigé ici aussi. */}
            {t.wazuh?.alert_url?.startsWith('https://') && (
              <a className="btn-link" href={t.wazuh.alert_url} target="_blank" rel="noopener noreferrer">
                {tr("Ouvrir l'alerte dans Wazuh")}<span aria-hidden="true"> ↗</span><span className="sr-only"> {tr("(nouvel onglet)")}</span>
              </a>
            )}
            <button type="button" onClick={exportIodef}>{tr("Exporter (IODEF JSON)")}</button>
          </div>
        )}
        {isTeam && (
          <dl className="ticket-facts">
            {t.due_qualification && <Deadline label={tr("Qualifier avant")} iso={t.due_qualification} />}
            {t.due_resolution && <Deadline label={tr("Résoudre avant")} iso={t.due_resolution} />}
            <div>
              <dt>{tr('Assigné à')}</dt>
              <dd>{t.assignee
                ? <>{t.assignee}{t.assignee_active === false ? ` ${tr('(inactif)')}` : ''}</>
                : open ? <span className="pill warn">{tr('Non assigné')}</span> : tr('Personne')}</dd>
            </div>
          </dl>
        )}
      </header>
      {/* Zone live conservée pour les lecteurs d'écran ; le retour visible est au bouton de chaque section. */}
      <p className="sr-only" role="status" aria-live="polite">{notice}</p>
      {dialog}
      {t.rex_en_attente && <p className="banner warn">{tr("Incident {sev} clôturé : le retour d'expérience est obligatoire (section Synthèse).", { sev: tr(t.gravite || t.criticite_initiale) })}</p>}

      {t.crisis && <p className="banner danger" role="status">{tr("MODE CRISE actif sur ce ticket : toute décision et toute action sont consignées dans le registre de crise.")}</p>}
      <PhaseContext.Provider value={phase}>
      <UnsavedProvider value={unsaved.report}>
      {isTeam ? (
        <>
          {/* Barre fixe : identité du ticket, étapes du cycle de vie, retour d'action et onglets restent à l'écran
              quand on fait défiler la page (ADR-0026). */}
          <div className="ticket-sticky">
            <div className="ticket-bar-top">
              <div className="ticket-bar-id"><span className="mono strong">{t.ref}</span><span className="title muted">{t.title}</span></div>
              <div className="head-status"><UnsavedSummary labels={unsaved.labels} /><ActionStatus state={headStatus} /></div>
              <div className="row wrap gap ticket-steps">
                {/* Un seul bouton primaire : l'étape suivante normale, placée en dernier ; l'issue alternative est secondaire. */}
                {[...(TRANSITIONS[t.status] || [])].sort((a, b) => (a === MAIN_NEXT[t.status]) - (b === MAIN_NEXT[t.status])).map((s) => (
                  <button type="button" key={s} className={s === MAIN_NEXT[t.status] ? 'primary' : undefined} onClick={() => transition(s)}>
                    → {STATUS[s].label}
                  </button>
                ))}
              </div>
            </div>
            <TabBar idBase="ticket" label={tr('Sections de la fiche')} active={tab} onSelect={selectTab}
              tabs={TABS.map((x) => ({
                id: x.id, label: tr(x.label),
                badge: <>
                  {x.id === 'preuves' && t.attachments.length > 0 && <span className="count">{t.attachments.length}</span>}
                  {x.id === 'communication' && t.comments.length > 0 && <span className="count">{t.comments.length + (t.comments_older || 0)}</span>}
                  {x.id === 'rex' && t.rex_required && <span className="pill warn">{tr('obligatoire')}</span>}
                  {x.zones.some((z) => unsaved.ids.includes(z)) && <span className="unsaved-dot"><span aria-hidden="true">●</span><span className="sr-only"> {tr('Modifications non enregistrées')}</span></span>}
                </>,
              }))} />
          </div>
          <TabPanel id="general" idBase="ticket" active={tab === 'general'}>
            <div className="ticket-layout">
              <div className="ticket-main">
                <Crisis t={t} enc={enc} isManager={me.role === 'manager'} open={open} onChange={load} />
                <Description t={t} enc={enc} canEdit={open} run={run} onImage={uploadImage} alertMerged={alertMerged} />
              </div>
              <aside className="ticket-aside" aria-label={tr("Pilotage du ticket")}>
                <Qualification t={t} enc={enc} run={run} open={open} />
                <Assignment t={t} enc={enc} run={run} open={open} />
                <Links t={t} enc={enc} run={run} open={open} />
                <Details t={t} />
              </aside>
            </div>
          </TabPanel>
          <TabPanel id="investigation" idBase="ticket" active={tab === 'investigation'}>
            {!alertMerged && <AlertBlock t={t} />}
            {t.wazuh?.context && <WazuhContext t={t} enc={enc} run={run} open={open} />}
            <Mitre t={t} enc={enc} run={run} open={open} />
            <IsiPanel t={t} enc={enc} run={run} open={open} />
            {alertMerged && !t.wazuh?.context && <p className="muted">{tr("L'alerte Wazuh est reprise dans la description (onglet Vue générale).")}</p>}
          </TabPanel>
          <TabPanel id="preuves" idBase="ticket" active={tab === 'preuves'}>
            <Attachments t={t} enc={enc} me={me} run={run} vt={vt} />
            {vt && <VirusTotalPanel t={t} enc={enc} vt={vt} />}
            <Events t={t} />
          </TabPanel>
          <TabPanel id="communication" idBase="ticket" active={tab === 'communication'}>
            <Comments t={t} enc={enc} isClient={isClient} me={me} run={run} onImage={uploadImage} templates={templates('commentaire')} />
          </TabPanel>
          <TabPanel id="rex" idBase="ticket" active={tab === 'rex'}>
            <Synthese t={t} enc={enc} run={run} onImage={uploadImage} templates={templates('synthese')} />
          </TabPanel>
        </>
      ) : (
        // Portail client : peu de contenu, une seule page, sans onglets.
        <>
        <div className="head-status"><UnsavedSummary labels={unsaved.labels} /></div>
        <div className="ticket-layout ticket-client">
          <div className="ticket-main">
            <Description t={t} enc={enc} canEdit={false} run={run} onImage={uploadImage} alertMerged={false} />
            <Attachments t={t} enc={enc} me={me} run={run} vt={vt} />
            <Events t={t} />
            <Comments t={t} enc={enc} isClient={isClient} me={me} run={run} onImage={uploadImage} templates={templates('commentaire')} />
          </div>
        </div>
        </>
      )}
      </UnsavedProvider>
      </PhaseContext.Provider>
    </>
  )
}

function BodyHistory({ enc, current }) {
  const [h, setH] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { api(`/tickets/${enc}/body-history`).then(setH).catch((e) => setError(e.message)) }, [enc, current])
  if (error) return <p className="error" role="alert">{error}</p>
  if (!h) return <p className="muted small">{tr("Chargement…")}</p>
  if (h.versions.length === 0) return <p className="muted small">{tr("Aucune modification depuis la création du ticket.")}</p>
  return (
    <ol className="versions" aria-label={tr("Versions de la description")}>
      {[...h.versions].reverse().map((v, i) => (
        <li key={v.ts + i}>
          <details>
            <summary>{tr("Avant la modification du")} <span className="mono">{formatUtc(v.ts)}</span> {tr("par")} <strong>{v.actor}</strong>{v.truncated ? tr(' (aperçu tronqué)') : ''}</summary>
            <Html html={v.html} />
            {v.truncated && <p className="muted small">{tr('Version complète de {n} caractères ; empreinte SHA-256', { n: v.length })} <span className="mono">{v.sha256}</span>.</p>}
          </details>
        </li>
      ))}
    </ol>
  )
}

function Description({ t, enc, canEdit, run, onImage, alertMerged }) {
  const [status, track] = useActionStatus()
  const [editing, setEditing] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [html, setHtml] = useState(t.body_html)
  const isTeam = t.raw_alerts !== undefined
  const dirty = editing && html !== t.body_html
  useUnsaved('description', tr('description'), dirty)
  return (
    <Section id="description" title={tr("Description")} summary={<UnsavedBadge show={dirty} />} tools={(isTeam || (canEdit && !editing)) && <>
      {isTeam && <button type="button" aria-expanded={showHistory} onClick={() => setShowHistory(!showHistory)}>{showHistory ? tr("Masquer l'historique") : tr('Historique')}</button>}
      {canEdit && !editing && <button type="button" onClick={() => { setHtml(t.body_html); setEditing(true) }}>{tr("Modifier")}</button>}</>}>
      {showHistory && <BodyHistory enc={enc} current={t.body_html} />}
      {editing ? (
        <>
          <RichEditor value={html} onChange={setHtml} label={tr("Description du ticket")} onImage={onImage} minHeight={200} />
          <div className="row gap end">
            <button type="button" onClick={() => setEditing(false)}>{tr("Annuler")}</button>
            <button type="button" className="primary" onClick={async () => {
              if (await track(() => run(() => api(`/tickets/${enc}/body`, { method: 'PUT', json: { body_html: html } }), tr('Description enregistrée (version précédente conservée).')))) setEditing(false)
            }}>{tr("Enregistrer")}</button>
          </div>
          {status?.error && <ActionStatus state={status} />}
        </>
      ) : <Html html={t.body_html} />}
      {!editing && status?.ok && <p className="saved-note"><ActionStatus state={status} /></p>}
      {alertMerged && (
        // La description reprend déjà la règle, sa description et l'agent : seules les autres données de l'alerte sont ajoutées.
        <div className="alert-extra">
          <h3>{tr("Autres données de l'alerte Wazuh")}</h3>
          <dl className="kv">
            <dt>{tr("Groupes")}</dt><dd className="mono">{t.rule.groups.join(', ') || '—'}</dd>
            <dt>{tr("Classification")}</dt><dd className="mono small">{t.classification.join(', ') || '—'}</dd>
          </dl>
          <p className="muted small">{tr('{n} alerte(s) brute(s) conservée(s) avec empreinte SHA-256', { n: t.raw_alerts })}</p>
        </div>
      )}
    </Section>
  )
}

function AlertBlock({ t }) {
  return (
    <Section id="alerte" title={tr("Alerte Wazuh")} summary={tr('{n} alerte(s) brute(s) conservée(s) avec empreinte SHA-256', { n: t.raw_alerts })}>
      <dl className="kv">
        <dt>{tr("Règle")}</dt><dd className="mono">{tr('{id} · niveau {level}', { id: t.rule.id, level: t.rule.level })}</dd>
        <dt>{tr("Description")}</dt><dd>{t.rule.description}</dd>
        <dt>{tr("Groupes")}</dt><dd className="mono">{t.rule.groups.join(', ') || '—'}</dd>
        <dt>{tr("Agent")}</dt><dd className="mono">{[t.agent.id, t.agent.name, t.agent.ip].filter(Boolean).join(' · ') || '—'}</dd>
        <dt>{tr("Classification")}</dt><dd className="mono small">{t.classification.join(', ') || '—'}</dd>
      </dl>
    </Section>
  )
}

function Attachments({ t, enc, me, run, vt }) {
  const isClient = me.role === 'client'
  const isTeam = !isClient
  const [form, setFormState] = useState(null)
  const [ext, setExtState] = useState(null)
  // Formulaires non contrôlés : « modifié » dès la première saisie, remis à zéro à l'ouverture, à l'annulation et au succès.
  const [formDirty, setFormDirty] = useState(false)
  const [extDirty, setExtDirty] = useState(false)
  const setForm = (v) => { setFormState(v); setFormDirty(false) }
  const setExt = (v) => { setExtState(v); setExtDirty(false) }
  useUnsaved('piece', tr('dépôt de pièce'), !!form && formDirty)
  useUnsaved('preuve-externe', tr('preuve externe'), !!ext && extDirty)
  const [status, track] = useActionStatus()          // dépôt et déclaration : à côté du bouton du formulaire
  const [rowStatus, setRowStatus] = useState(null)   // { id, ok | error } : dans la ligne de la pièce concernée
  const [ask, dialog] = useConfirm()

  const fetchContent = async (a, params) => {
    const blob = await api(`/attachments/${a.id}/content`, { params })
    downloadBlob(blob, a.filename + (a.scan_status === 'quarantaine' ? '.quarantaine.zip' : ''))
  }
  const download = async (a) => {
    const quarantined = a.scan_status === 'quarantaine'
    setRowStatus(null)
    if (a.kind !== 'fichier' && !quarantined) {   // image insérée dans un texte : pas de motif demandé
      try { await fetchContent(a, {}) } catch (e) { setRowStatus({ id: a.id, error: e.message }) }
      return
    }
    await ask({
      title: quarantined
        ? tr('Télécharger « {name} », détecté comme malveillant ?', { name: a.filename })
        : tr('Télécharger « {name} »', { name: a.filename }),
      body: <>
        {quarantined && <p>{tr("Le fichier sera fourni dans une archive ZIP chiffrée (mot de passe : voir le guide d'exploitation), pour analyse uniquement.")}</p>}
        <p>{tr("Le téléchargement et son motif sont inscrits dans la chaîne de possession de la pièce.")}</p>
      </>,
      fields: [{ name: 'motif', label: tr('Motif du téléchargement (chaîne de possession)'), minLength: 3, maxLength: 500 }],
      confirm: tr('Télécharger'), danger: quarantined,
      action: ({ motif }) => fetchContent(a, quarantined ? { motif, confirmer_malveillant: 'true' } : { motif }),
    })
  }

  const lifecycle = async (a, value) => {
    const destroy = value === 'detruit'
    setRowStatus(null)
    // Une phrase complète par état : pas de mot construit par concaténation (intraduisible).
    const r = await ask({
      title: destroy
        ? tr('Détruire définitivement la pièce « {name} » ?', { name: a.filename })
        : tr('Restituer la pièce « {name} » ?', { name: a.filename }),
      body: <p>{destroy
        ? tr("Le contenu de la pièce est effacé de Keryx et ne pourra pas être récupéré. Sa ligne, son empreinte et sa chaîne de possession restent au registre.")
        : tr("La pièce est marquée comme restituée : elle ne pourra plus être téléchargée depuis Keryx. L'opération est inscrite dans la chaîne de possession.")}</p>,
      fields: [{ name: 'reason', label: destroy ? tr('Motif de la destruction') : tr('Motif de la restitution'), minLength: 3, maxLength: 500 }],
      confirm: destroy ? tr('Détruire la pièce') : tr('Restituer la pièce'), danger: destroy,
      action: ({ reason }) => run(() => api(`/attachments/${a.id}/lifecycle`, { method: 'POST', json: { lifecycle: value, reason } }), destroy ? tr('Pièce détruite.') : tr('Pièce restituée.')),
    })
    if (r) setRowStatus({ id: a.id, ok: destroy ? tr('Pièce détruite à {h}', { h: utcClock() }) : tr('Pièce restituée à {h}', { h: utcClock() }) })
  }

  const submit = async (e) => {
    e.preventDefault()
    const fd = new FormData(e.target)
    fd.set('collected_at', utcInputToIso(fd.get('collected_at')))
    if (!isClient) fd.set('visible_client', fd.get('visible_client') ? 'true' : 'false')
    if (await track(() => run(() => api(`/tickets/${enc}/attachments`, { method: 'POST', form: fd }), tr('Pièce déposée.')), tr('Pièce déposée à {h}', { h: utcClock() }))) setForm(null)
  }

  const submitExt = async (e) => {
    e.preventDefault()
    const fd = Object.fromEntries(new FormData(e.target))
    const json = { ...fd, collected_at: utcInputToIso(fd.collected_at), size: Number(fd.size || 0), sha256: fd.sha256.toLowerCase() }
    if (await track(() => run(() => api(`/tickets/${enc}/preuves-externes`, { method: 'POST', json }), tr('Preuve externe déclarée.')), tr('Preuve externe déclarée à {h}', { h: utcClock() }))) setExt(null)
  }

  return (
    <Section id="preuves" title={isClient ? tr('Éléments déposés') : tr('Registre des preuves')} summary={<>{t.attachments.length || null}<UnsavedBadge show={(!!form && formDirty) || (!!ext && extDirty)} /></>} tools={<>
        {isTeam && <button type="button" onClick={() => { setExt(true); setForm(null) }}>{tr("Déclarer une preuve externe")}</button>}
        <button type="button" className="dark" onClick={() => { setForm(true); setExt(null) }}>{tr('Déposer un fichier ({n} Mo max)', { n: t.attachment_max_mb ?? 20 })}</button>
      </>}>
      {form && (
        <form className="subform" onSubmit={submit} onInput={() => setFormDirty(true)}>
          <label>{tr("Fichier (archive ZIP, PNG, JPEG ou WebP)")}<input type="file" name="file" accept=".zip,image/png,image/jpeg,image/webp" required /></label>
          <label>{tr("Description (obligatoire)")}<input name="description" minLength={3} required /></label>
          <div className="grid2">
            <label>{tr("Date et heure de collecte (UTC)")}<input type="datetime-local" name="collected_at" defaultValue={utcInputNow()} required /></label>
            <label>{tr("Sensibilité")}<select name="sensitivity" defaultValue={tlpAuMoins(t.tlp, t.tlp_plancher)}>{TLPS.map((x) => <option key={x} disabled={tlpSous(x, t.tlp_plancher)}>{x}</option>)}</select></label>
          </div>
          <label>{tr("Méthode de collecte (obligatoire)")}<input name="method" minLength={3} placeholder={tr("ex. export du journal du pare-feu")} required /></label>
          {!isClient && <label className="check"><input type="checkbox" name="visible_client" value="true" /> {tr("Visible par le client")}</label>}
          <p className="muted small">{tr("L'archive n'est jamais décompressée par Keryx. Analyse antivirus automatique quand ClamAV est configuré.")}</p>
          <div className="row gap end"><button type="button" onClick={() => setForm(null)}>{tr("Annuler")}</button><button className="primary">{tr("Déposer")}</button></div>
          {status?.error && <ActionStatus state={status} />}
        </form>
      )}
      {ext && (
        <form className="subform" onSubmit={submitExt} onInput={() => setExtDirty(true)}>
          <p className="muted small">{tr('Pour une preuve de plus de {n} Mo (image disque, dump mémoire, pcap) conservée hors de Keryx, sur un support hors ligne.', { n: t.attachment_max_mb ?? 20 })}</p>
          <label>{tr("Nom")}<input name="filename" required /></label>
          <label>{tr("Description")}<input name="description" minLength={3} required /></label>
          <div className="grid2">
            <label>{tr("Date et heure de collecte (UTC)")}<input type="datetime-local" name="collected_at" defaultValue={utcInputNow()} required /></label>
            <label>{tr("Taille (octets)")}<input type="number" name="size" min="0" /></label>
          </div>
          <label>{tr("Méthode de collecte")}<input name="method" minLength={3} required /></label>
          <label>{tr("Empreinte SHA-256")}<input name="sha256" pattern="[0-9a-fA-F]{64}" className="mono" required /></label>
          <label>{tr("Lieu de conservation")}<input name="location" minLength={3} placeholder={tr("ex. coffre hors ligne n°2")} required /></label>
          <label>{tr("Sensibilité")}<select name="sensitivity" defaultValue={tlpAuMoins(t.tlp, t.tlp_plancher)}>{TLPS.map((x) => <option key={x} disabled={tlpSous(x, t.tlp_plancher)}>{x}</option>)}</select></label>
          <div className="row gap end"><button type="button" onClick={() => setExt(null)}>{tr("Annuler")}</button><button className="primary">{tr("Déclarer")}</button></div>
          {status?.error && <ActionStatus state={status} />}
        </form>
      )}
      {!form && !ext && status?.ok && <p className="saved-note"><ActionStatus state={status} /></p>}
      {t.attachments.length === 0 ? <p className="muted">{tr("Aucune pièce.")}</p> : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th scope="col">{tr("Élément")}</th><th scope="col">{tr("Collecte · méthode")}</th><th scope="col">{tr("SHA-256")}</th><th scope="col">{tr("Antivirus")}</th><th scope="col">{tr("Sort")}</th><th scope="col"><span className="sr-only">{tr("Actions")}</span></th></tr></thead>
            <tbody>
              {t.attachments.map((a) => (
                <tr key={a.id}>
                  <td><strong>{a.filename}</strong><div className="muted small">{a.description} · {a.sensitivity}{a.location ? ` · ${a.location}` : ''}</div></td>
                  <td className="small">{formatUtc(a.collected_at)}<div className="muted">{a.method}</div></td>
                  <td className="small"><span className="mono" title={a.sha256}>{a.sha256.slice(0, 12)}…{a.sha256.slice(-6)}</span>
                    {a.lifecycle === 'conserve' && <Stamps attachmentId={a.id} canStamp={isTeam && !!me.features?.timestamping} />}</td>
                  <td><span className={`pill ${a.scan_status === 'quarantaine' ? 'danger' : a.scan_status === 'sain' ? 'ok' : ''}`}>{SCAN[a.scan_status]}</span></td>
                  <td>{a.kind === 'preuve_externe' ? tr('Hors Keryx') : LIFECYCLE[a.lifecycle]}</td>
                  <td>
                    <div className="row gap wrap">
                      {a.kind !== 'preuve_externe' && a.lifecycle === 'conserve' && !(isClient && a.scan_status === 'quarantaine') &&
                        <button type="button" className="small-btn" onClick={() => download(a)}>{tr("Télécharger")}</button>}
                      {isTeam && a.lifecycle === 'conserve' && <button type="button" className="small-btn" onClick={() => lifecycle(a, 'restitue')}>{tr("Restituer")}</button>}
                      {/* Seule l'empreinte de la pièce part vers VirusTotal ; c'est le serveur qui la prend. */}
                      <VtPieceButton vt={vt} a={a} />
                      {me.role === 'manager' && a.lifecycle !== 'detruit' && <button type="button" className="small-btn danger" onClick={() => lifecycle(a, 'detruit')}>{tr("Détruire")}</button>}
                    </div>
                    {rowStatus?.id === a.id && <ActionStatus state={rowStatus} />}
                    <VtPieceState vt={vt} a={a} lookups={t.virustotal?.lookups} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">{tr("Chaque dépôt, téléchargement, restitution ou destruction est inscrit dans la chaîne de possession.")}</p>
      {dialog}
    </Section>
  )
}

function Synthese({ t, enc, run, onImage, templates }) {
  const s = t.synthese || {}
  const [v, setV] = useState({
    compromission_initiale: isoToUtcInput(s.compromission_initiale),
    chronologie: s.chronologie || '', mode_operatoire: s.mode_operatoire || '', perimetre: s.perimetre || '', rex_html: s.rex_html || '',
  })
  const [status, track] = useActionStatus()
  const editable = !['faux_positif', 'retour_experience'].includes(t.status)
  const [saved, setSaved] = useState(v)   // dernier état enregistré
  const dirty = editable && JSON.stringify(v) !== JSON.stringify(saved)
  useUnsaved('synthese', tr('synthèse'), dirty)
  const save = async () => {
    if (await track(() => run(() => api(`/tickets/${enc}/synthese`, {
      method: 'PUT',
      json: { ...v, compromission_initiale: utcInputToIso(v.compromission_initiale) },
    }), tr('Synthèse enregistrée.')))) setSaved(v)
  }
  const rexNote = t.rex_required ? <span className="pill warn">{tr("REX obligatoire")}</span> : null
  if (!editable) {
    return (
      <Section id="synthese" title={tr("Synthèse de l'incident et retour d'expérience")}>
        <h3>{tr("Chronologie")}</h3><Html html={s.chronologie} />
        <h3>{tr("Mode opératoire")}</h3><Html html={s.mode_operatoire} />
        <h3>{tr("Périmètre")}</h3><Html html={s.perimetre} />
        <h3>{tr("Retour d'expérience")}</h3><Html html={s.rex_html} />
      </Section>
    )
  }
  return (
    <Section id="synthese" title={tr("Synthèse de l'incident et retour d'expérience")} summary={<>{rexNote}<UnsavedBadge show={dirty} /></>}>
      <p className="muted small">{tr("PRIS VI.5.3.e · ISO 27035")}</p>
      <label>{tr("Date de compromission initiale (UTC)")}
        <input type="datetime-local" value={v.compromission_initiale} onChange={(e) => setV({ ...v, compromission_initiale: e.target.value })} />
      </label>
      <h3>{tr("Chronologie")}</h3>
      <RichEditor value={v.chronologie} onChange={(x) => setV({ ...v, chronologie: x })} label={tr("Chronologie")} templates={templates} minHeight={80} />
      <h3>{tr("Mode opératoire")}</h3>
      <RichEditor value={v.mode_operatoire} onChange={(x) => setV({ ...v, mode_operatoire: x })} label={tr("Mode opératoire")} templates={templates} minHeight={80} />
      <h3>{tr("Périmètre")}</h3>
      <RichEditor value={v.perimetre} onChange={(x) => setV({ ...v, perimetre: x })} label={tr("Périmètre")} templates={templates} minHeight={80} />
      <h3>{tr("Retour d'expérience")} {t.rex_required && <span className="pill warn">{tr("obligatoire")}</span>}</h3>
      <RichEditor value={v.rex_html} onChange={(x) => setV({ ...v, rex_html: x })} label={tr("Retour d'expérience")} templates={templates} onImage={onImage} minHeight={80} />
      <div className="row gap end wrap"><ActionStatus state={status} /><button type="button" className="primary" onClick={save}>{tr("Enregistrer la synthèse")}</button></div>
    </Section>
  )
}

function fmtDetail(v) {
  if (v === null || v === undefined || v === '') return '—'
  if (Array.isArray(v)) return v.map(fmtDetail).join(', ')
  if (typeof v === 'object') return Object.entries(v).map(([k, x]) => `${k} : ${fmtDetail(x)}`).join(', ')
  return String(v)
}

// Entrées plus anciennes d'un ticket (commentaires ou historique), chargées à la demande par paquets : la fiche ne
// reçoit que les plus récentes. Un nouveau relevé de la fiche repart des plus récentes.
function useOlder(ref, kind, items, older) {
  // Les entrées ajoutées sont liées à la liste reçue avec la fiche : une fiche relue les efface dès le rendu suivant,
  // et une réponse arrivée après une relecture est ignorée.
  const [extra, setExtra] = useState({ base: items, items: [], older: null, error: '' })
  const [busy, setBusy] = useState(false)
  const current = extra.base === items ? extra : { base: items, items: [], older: null, error: '' }
  const all = [...current.items, ...items]
  const remaining = current.older ?? older ?? 0
  const error = current.error
  const more = async () => {
    setBusy(true)
    try {
      const r = await api(`/tickets/${encodeURIComponent(ref)}/${kind}`, { params: { before: all[0].id } })
      // Liée à la liste de la fiche au moment de la demande : si la fiche a été relue entre-temps, `base` ne correspond
      // plus et ces entrées ne sont pas affichées.
      setExtra((x) => ({ base: items, items: [...r.items, ...(x.base === items ? x.items : [])], older: r.older, error: '' }))
    } catch (e) {
      setExtra((x) => ({ ...(x.base === items ? x : { base: items, items: [], older: null }), error: e.message }))
    } finally { setBusy(false) }
  }
  const button = remaining > 0 && (
    <p className="row gap older">
      <button type="button" className="small-btn" onClick={more} disabled={busy}>{tr('Afficher les plus anciens ({n} restants)', { n: remaining })}</button>
      {error && <span className="error" role="alert">{error}</span>}
    </p>
  )
  return { all, total: items.length + (older || 0), button }
}

function Events({ t }) {
  const ev = useOlder(t.ref, 'events', t.events, t.events_older)
  return (
    <Section id="actions" title={tr("Registre des actions")} summary={ev.total || null}>
      {ev.button}
      <ol className="timeline">
        {ev.all.map((e, i) => (
          <li key={e.id || i}>
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

function Comments({ t, enc, isClient, me, run, onImage, templates }) {
  // Brouillon de la zone de saisie : sessionStorage de l'onglet seulement (ADR-0024), restauré au retour sur la fiche.
  const cm = useOlder(t.ref, 'comments', t.comments, t.comments_older)
  const key = draftKey(me.username, t.ref)
  const [html, setHtmlState] = useState(() => readDraft(key))
  const [restored, setRestored] = useState(() => !!readDraft(key))
  const setHtml = (v) => { setHtmlState(v); writeDraft(key, v); setRestored(false) }
  const [visible, setVisible] = useState(isClient)
  const [status, track, setStatus] = useActionStatus()
  const [ask, dialog] = useConfirm()
  const dirty = !!html.trim()
  useUnsaved('commentaire', tr('commentaire'), dirty)
  const post = async () => {
    if (!html.trim()) { setStatus({ error: tr('Le commentaire est vide.') }); return }
    const send = () => run(() => api(`/tickets/${enc}/comments`, { method: 'POST', json: { body_html: html, visible_client: visible } }), tr('Commentaire publié.'))
    let ok
    if (!isClient && visible) {
      // Un commentaire visible par le client ne peut ni être modifié ni être retiré : la confirmation nomme le client.
      const r = await ask({
        title: tr('Publier ce commentaire au client {client} ?', { client: t.client }),
        body: <p>{tr("Ce commentaire sera lu par les utilisateurs du client {client}. Il ne pourra plus être modifié ni retiré. Pour un échange interne, décocher « Visible par le client ».", { client: t.client })}</p>,
        confirm: tr('Publier au client {client}', { client: t.client }),
        action: send,
      })
      ok = !!r
      if (ok) track(async () => {}, tr('Publié à {h}', { h: utcClock() }))
    } else {
      ok = await track(send, tr('Publié à {h}', { h: utcClock() }))
    }
    if (ok) { writeDraft(key, ''); setHtmlState(''); setRestored(false) }
  }
  const saveTemplate = async () => {
    const r = await ask({
      title: tr('Enregistrer ce commentaire comme modèle pour {client}', { client: t.client }),
      body: <p>{tr("Le modèle sera proposé dans l'éditeur des commentaires de ce client, pour toute l'équipe.")}</p>,
      fields: [{ name: 'name', label: tr('Nom du modèle (propre à ce client)'), maxLength: 120 }],
      confirm: tr('Enregistrer le modèle'),
      action: ({ name }) => run(() => api('/templates', { method: 'POST', json: { kind: 'commentaire', name, body_html: html, client: t.client_key } }), tr('Modèle enregistré.')),
    })
    if (r) setStatus({ ok: tr('Modèle enregistré à {h}', { h: utcClock() }) })
  }
  return (
    <Section id="commentaires" title={isClient ? tr('Échanges avec le SOC') : tr('Commentaires')} summary={cm.total || null}>
      {cm.total === 0 && <p className="muted">{tr("Aucun commentaire.")}</p>}
      {cm.button}
      {cm.all.map((c, i) => (
        <div key={c.id || i} className={`comment ${c.visible_client ? 'public' : 'internal'}`}>
          <div className="comment-head">{c.visible_client ? (isClient ? '' : tr('VISIBLE CLIENT · ')) : tr('INTERNE · ')}{c.author} · {formatUtc(c.created_at)}</div>
          <Html html={c.body_html} />
        </div>
      ))}
      <h3>{isClient ? tr('Votre réponse') : tr('Nouveau commentaire')} <UnsavedBadge show={dirty} /></h3>
      {restored && <p className="muted small" role="status">{tr("Brouillon retrouvé : il n'a pas été publié. Il reste dans cet onglet seulement.")}</p>}
      <RichEditor value={html} onChange={setHtml} label={tr("Nouveau commentaire")} templates={templates} onImage={onImage} />
      <div className="row gap between">
        {!isClient ? <label className="check"><input type="checkbox" checked={visible} onChange={(e) => setVisible(e.target.checked)} /> {tr("Visible par le client")}</label> : <span />}
        <div className="row gap">
          {!isClient && <button type="button" onClick={saveTemplate} disabled={!html.trim()}>{tr("Enregistrer comme modèle")}</button>}
          <button type="button" className="dark" onClick={post}>{tr("Publier")}</button>
        </div>
      </div>
      <div className="row end"><ActionStatus state={status} /></div>
      {dialog}
      {!isClient && <p className="muted small">{tr("Mentionnez un collègue avec @identifiant : il recevra une notification.")}</p>}
    </Section>
  )
}

function Qualification({ t, enc, run, open }) {
  const { me } = useAuth()
  const [v, setV] = useState({ verdict: t.verdict || '', dommages: t.dommages || '', importance: t.importance, impact: t.impact || '', risque: t.risque || '', tlp: t.tlp })
  // TLP plancher du client (ADR-0033) : l'analyste ne descend pas en dessous ; le manager le peut, avec un motif.
  const [motifTlp, setMotifTlp] = useState('')
  const sousPlancher = v.tlp !== t.tlp && tlpSous(v.tlp, t.tlp_plancher)
  const verdictLocked = !['nouveau', 'en_evaluation'].includes(t.status)
  const [status, track] = useActionStatus()
  // Modifié = différent de ce que la fiche affiche (rechargée après un enregistrement).
  const dirty = open && (v.verdict !== (t.verdict || '') || v.dommages !== (t.dommages || '') || v.importance !== t.importance
    || v.impact !== (t.impact || '') || v.risque !== (t.risque || '') || v.tlp !== t.tlp)
  useUnsaved('qualification', tr('qualification'), dirty)
  const save = () => {
    const json = { importance: v.importance, impact: v.impact, risque: v.risque, tlp: v.tlp }
    if (sousPlancher) json.motif_tlp = motifTlp
    if (v.verdict && !verdictLocked) json.verdict = v.verdict
    if (v.dommages) json.dommages = v.dommages
    track(() => run(() => api(`/tickets/${enc}/qualification`, { method: 'POST', json }), tr('Qualification enregistrée.')))
  }
  return (
    <Section id="qualification" title={tr("Qualification")} summary={<>{t.verdict ? VERDICTS[t.verdict] : <span className="pill warn">{tr("À qualifier")}</span>}<UnsavedBadge show={dirty} /></>}>
      <label>{tr("Verdict")}
        <select value={v.verdict} disabled={!open || verdictLocked} onChange={(e) => setV({ ...v, verdict: e.target.value })}>
          <option value="">{tr("À qualifier")}</option>
          {Object.entries(VERDICTS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
      </label>
      {verdictLocked && open && <p className="muted small">{tr("Verdict figé hors de la phase d'évaluation.")}</p>}
      <div className="grid2">
        <label>{tr("Dommages")}
          <select value={v.dommages} disabled={!open} onChange={(e) => setV({ ...v, dommages: e.target.value })}>
            <option value="">—</option>
            {Object.entries(DOMMAGES).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </label>
        <label>{tr("Importance")}
          <select value={v.importance} disabled={!open} onChange={(e) => setV({ ...v, importance: e.target.value })}>
            {Object.entries(IMPORTANCES).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </label>
      </div>
      {t.severity_hint && open && (
        <p className="muted small" data-testid="severity-hint">{tr("Selon l'importance « {imp} » de l'équipement : dommages limités → {a}, significatifs → {b}, graves → {c} (grille du client). La gravité est fixée par votre qualification.", { imp: IMPORTANCES[v.importance], a: tr(t.severity_hint.limites), b: tr(t.severity_hint.significatifs), c: tr(t.severity_hint.graves) })}</p>
      )}
      {t.proposition && open && !t.dommages && (
        // Gravité proposée (ADR-0028) : jamais appliquée seule ; un clic la retient, et le registre dit qu'elle venait
        // de la proposition.
        <div className="proposal" data-testid="severity-proposal">
          <p className="small">{tr('Gravité proposée : {g}, avec des dommages « {d} » (d\'après la criticité initiale {c} et l\'importance de l\'équipement). À confirmer.', { g: tr(t.proposition.gravite), d: DOMMAGES[t.proposition.dommages], c: tr(t.proposition.criticite) })}</p>
          <button type="button" onClick={() => {
            setV({ ...v, dommages: t.proposition.dommages })
            track(() => run(() => api(`/tickets/${enc}/qualification`, { method: 'POST', json: { dommages: t.proposition.dommages, from_proposal: true } }), tr('Gravité proposée retenue.')))
          }}>{tr('Retenir cette gravité')}</button>
        </div>
      )}
      <div className="row between gravity"><span className="muted">{tr("Gravité qualifiée")}</span><Severity value={t.gravite} /></div>
      <label>{tr("Impact constaté")}<textarea rows="2" value={v.impact} disabled={!open} onChange={(e) => setV({ ...v, impact: e.target.value })} /></label>
      <label>{tr("Risque induit")}<textarea rows="2" value={v.risque} disabled={!open} onChange={(e) => setV({ ...v, risque: e.target.value })} /></label>
      <label>{tr("Marquage")}<select value={v.tlp} disabled={!open} aria-describedby={t.tlp_plancher ? `tlp-plancher-${t.ref}` : undefined}
        onChange={(e) => setV({ ...v, tlp: e.target.value })}>
        {TLPS.map((x) => <option key={x} disabled={me.role !== 'manager' && x !== t.tlp && tlpSous(x, t.tlp_plancher)}>{x}</option>)}
      </select></label>
      {t.tlp_plancher && <p className="field-hint" id={`tlp-plancher-${t.ref}`}>{me.role === 'manager'
        ? tr('TLP plancher de ce client : {p}. Descendre en dessous demande un motif, inscrit au registre.', { p: t.tlp_plancher })
        : tr('TLP plancher de ce client : {p}. On peut monter, pas descendre en dessous (politique fixée par le manager).', { p: t.tlp_plancher })}</p>}
      {sousPlancher && me.role === 'manager' && (
        <label>{tr('Motif du passage sous le TLP plancher (10 caractères au moins)')}
          <textarea rows="2" value={motifTlp} required minLength={10} onChange={(e) => setMotifTlp(e.target.value)} />
        </label>
      )}
      {open && <button type="button" className="primary wide" onClick={save}>{tr("Enregistrer")}</button>}
      <ActionStatus state={status} />
    </Section>
  )
}

function Mitre({ t, enc, run, open }) {
  const [text, setText] = useState(t.mitre.join(', '))
  const canon = (x) => x.split(/[\s,;]+/).filter(Boolean).map((y) => y.toUpperCase()).join(',')
  const mitreDirty = open && canon(text) !== canon(t.mitre.join(','))
  useUnsaved('mitre', tr('MITRE'), mitreDirty)
  const [q, setQ] = useState('')
  const [found, setFound] = useState([])
  const [status, track] = useActionStatus()
  useEffect(() => {
    if (q.trim().length < 2) { setFound([]); return undefined }
    const h = setTimeout(() => api('/mitre/techniques', { params: { q } }).then((r) => setFound(r.items)).catch(() => setFound([])), 250)
    return () => clearTimeout(h)
  }, [q])
  return (
    <Section id="mitre" title={tr("MITRE ATT&CK")} summary={<>{t.mitre.length ? <span className="mono">{t.mitre.join(', ')}</span> : tr("À compléter.")}<UnsavedBadge show={mitreDirty} /></>}>
      {t.mitre_detail.length === 0 && <p className="muted">{tr("À compléter.")}</p>}
      {t.mitre_detail.map((m) => (
        <div key={m.id} className="mitre">
          <a className="mono chip" href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer">{m.id}</a>
          <span>{m.technique}</span>
          {m.tactics?.length > 0 && <span className="muted small">{m.tactics.join(', ')}</span>}
        </div>
      ))}
      <p className="muted small">{tr("Source :")} <strong>{MITRE_SOURCE[t.mitre_source]}</strong></p>
      {open && (
        <>
          <label>{tr("Rechercher une technique (nom ou identifiant)")}<input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={tr("ex. brute force")} /></label>
          {found.length > 0 && (
            <ul className="found">{found.map((f) => (
              <li key={f.id}><button type="button" className="link" onClick={() => { setText((x) => [...new Set([...x.split(/[\s,;]+/).filter(Boolean), f.id])].join(', ')); setQ('') }}>
                <span className="mono">{f.id}</span> {f.name}</button></li>))}</ul>
          )}
          <label>{tr("Techniques (ex. T1110, T1543.003)")}<input className="mono" value={text} onChange={(e) => setText(e.target.value)} /></label>
          <div className="row gap wrap">
            <button type="button" onClick={() => track(() => run(() => api(`/tickets/${enc}/mitre`, {
              method: 'POST', json: { techniques: text.split(/[\s,;]+/).filter(Boolean).map((x) => x.toUpperCase()) },
            }), tr('MITRE corrigé (tracé).')))}>{tr("Corriger (tracé)")}</button>
            <ActionStatus state={status} />
          </div>
        </>
      )}
    </Section>
  )
}

function Assignment({ t, enc, run, open }) {
  const [people, setPeople] = useState([])
  const [status, track] = useActionStatus()
  useEffect(() => { api(`/tickets/${enc}/assignables`).then((r) => setPeople(r.items)).catch(() => {}) }, [enc])
  return (
    <Section id="affectation" title={tr("Affectation")} summary={t.assignee || tr('Personne')}>
      <label>{tr('Assigné à')}
        {/* Valeur fondée sur l'identifiant de l'assigné (unique), pas sur son nom affiché (deux comptes peuvent porter le même). */}
        <select disabled={!open} value={t.assignee_username || ''}
          onChange={(e) => { const username = e.target.value || null; track(() => run(() => api(`/tickets/${enc}/assign`, { method: 'POST', json: { username } }), tr('Affectation enregistrée.'))) }}>
          <option value="">{tr("Personne")}</option>
          {t.assignee_username && !people.some((p) => p.username === t.assignee_username) &&
            <option value={t.assignee_username} disabled>{t.assignee}{t.assignee_active === false ? ` ${tr('(inactif)')}` : ''}</option>}
          {people.map((p) => <option key={p.username} value={p.username}>{p.display_name}</option>)}
        </select>
      </label>
      <ActionStatus state={status} />
    </Section>
  )
}

const LINK_LABEL = { parent: tr('Parent'), enfant: tr('Enfant'), lie: tr('Lié'), doublon: tr('Doublon de'), 'doublon_de_celui-ci': tr('Doublon de ce ticket') }

function Links({ t, enc, run, open }) {
  const [items, setItems] = useState([])
  const [kind, setKind] = useState('lie')
  const [ref, setRef] = useState('')
  const [err, setErr] = useState('')
  const linkDirty = open && !!ref.trim()
  useUnsaved('lien', tr('lien'), linkDirty)
  const load = useCallback(() => api(`/tickets/${enc}/links`).then((r) => setItems(r.items)).catch(() => {}), [enc])
  useEffect(() => { load() }, [load, t.status])
  const add = async (e) => {
    e.preventDefault(); setErr('')
    try { setItems((await api(`/tickets/${enc}/links`, { method: 'POST', json: { ref: ref.trim().toUpperCase(), kind } })).items); setRef('') } catch (x) { setErr(x.message) }
  }
  const drop = async (id) => { try { setItems((await api(`/tickets/${enc}/links/${id}`, { method: 'DELETE' })).items) } catch (x) { setErr(x.message) } }
  const [ask, dialog] = useConfirm()
  const [status, setStatus] = useState(null)
  const merge = async () => {
    const r = await ask({
      title: tr('Fusionner {ref} dans un autre ticket et le clore comme doublon ?', { ref: t.ref }),
      body: <p>{tr("Les alertes brutes et les commentaires de {ref} sont rattachés au ticket conservé. {ref} est clos en faux positif (doublon) : l'opération ne s'annule pas.", { ref: t.ref })}</p>,
      fields: [
        { name: 'into', label: tr('Référence du ticket à conserver'), placeholder: tr('ACME-1'), mono: true, maxLength: 32,
          validate: (v) => (v.toUpperCase() === t.ref.toUpperCase() ? tr('Indiquer un autre ticket que celui-ci.') : '') },
        { name: 'reason', label: tr('Motif de la fusion'), minLength: 3, maxLength: 500 },
      ],
      confirm: tr('Fusionner et clore'), danger: true,
      action: ({ into, reason }) => run(() => api(`/tickets/${enc}/merge`, { method: 'POST', json: { into: into.toUpperCase(), reason } }), tr('Ticket fusionné.')),
    })
    if (r) setStatus({ ok: tr('Ticket fusionné dans {ref} à {h}', { ref: r.values.into.toUpperCase(), h: utcClock() }) })
  }
  return (
    <Section id="liens" title={tr("Tickets liés")} summary={<>{items.length || null}<UnsavedBadge show={linkDirty} /></>}>
      {items.length === 0 && <p className="muted small">{tr("Aucun lien.")}</p>}
      <ul className="linklist">
        {items.map((l) => (
          <li key={l.id}><span className="muted small">{LINK_LABEL[l.kind] || l.kind}</span>{' '}
            <Link to={`/tickets/${encodeURIComponent(l.ref)}`} className="mono">{l.ref}</Link>
            <button type="button" className="x" aria-label={tr('Supprimer le lien avec {ref}', { ref: l.ref })} onClick={() => drop(l.id)}>×</button></li>
        ))}
      </ul>
      {err && <p className="error" role="alert">{err}</p>}
      <form onSubmit={add} className="row gap wrap">
        <label className="grow">{tr("Référence")}<input value={ref} onChange={(e) => setRef(e.target.value)} placeholder={tr("ACME-2")} required /></label>
        <label>{tr("Type")}<select value={kind} onChange={(e) => setKind(e.target.value)}><option value="lie">{tr("Lié")}</option><option value="parent">{tr("Parent")}</option><option value="doublon">{tr("Doublon")}</option></select></label>
        <button>{tr("Lier")}</button>
      </form>
      {open && <button type="button" className="small-btn danger" onClick={merge}>{tr("Fusionner dans un autre ticket…")}</button>}
      <ActionStatus state={status} />
      {dialog}
    </Section>
  )
}

function Details({ t }) {
  return (
    <Section id="details" title={tr("Détails")}>
      {/* Les échéances et l'assigné sont dans l'en-tête de la fiche. */}
      <dl className="kv">
        <dt>{tr("Client")}</dt><dd>{t.client}</dd>
        <dt>{tr("Détecté (horloge Wazuh)")}</dt><dd className="mono small">{formatUtc(t.detected_at)}</dd>
        {t.received_at && <><dt>{tr("Reçu par Keryx")}</dt><dd className="mono small">{formatUtc(t.received_at)}</dd></>}
        <dt>{tr("Dernière occurrence")}</dt><dd className="mono small">{formatUtc(t.last_seen_at)}</dd>
        <dt>{tr("REX")}</dt><dd>{t.rex_required ? tr('Obligatoire') : tr('Non requis')}</dd>
      </dl>
    </Section>
  )
}
