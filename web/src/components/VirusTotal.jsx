import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'
import { isHash, lastFor, normalizeHash, shortHash, verdict, vtLink } from '../virustotal.js'
import { ActionStatus, useActionStatus } from './ActionStatus.jsx'
import { useConfirm } from './Confirm.jsx'
import Section from './Section.jsx'

// Recherche d'une empreinte sur VirusTotal (ADR-0022). Seule l'empreinte part, jamais le fichier ; la clé d'API est
// celle de l'utilisateur (profil). Réservé à l'analyste et au manager : rien de ce fichier n'est monté pour le client
// ni pour l'Admin (indicateur `features.virustotal` de /me). Ce que VirusTotal renvoie est une donnée non fiable :
// le serveur l'a ramené à des compteurs et à du texte borné, rendu ici comme du texte (jamais de HTML).
// Un fichier inconnu de VirusTotal, ou connu sans détection, n'est jamais présenté comme sain : pastille neutre et
// phrase explicite.

const ONLY_HASH = () => tr("Seule l'empreinte est envoyée, jamais le fichier.")

// Phrase complète d'un résultat (zone live, détail). Une phrase par cas : pas de mot construit par concaténation.
function sentence(l) {
  const v = verdict(l)
  if (v.kind === 'inconnu') return tr("Inconnu de VirusTotal : cette empreinte n'y figure pas. Cela ne dit rien du fichier, ni qu'il est dangereux, ni qu'il est sans danger.")
  if (v.kind === 'malveillant') return tr('{m} moteur(s) sur {n} signalent ce fichier comme malveillant.', { m: v.malicious, n: v.total })
  if (v.kind === 'suspect') return tr('{s} moteur(s) sur {n} jugent ce fichier suspect.', { s: v.suspicious, n: v.total })
  return tr("Aucune détection sur {n} moteur(s). Une absence de détection ne prouve pas que le fichier est sans danger.", { n: v.total })
}

// Pastille d'un résultat : rouge si des moteurs le signalent, ambre s'il est seulement jugé suspect, neutre sinon.
// Toujours avec son libellé : la couleur ne porte jamais seule l'information.
export function VtVerdict({ l }) {
  const v = verdict(l)
  const label = v.kind === 'inconnu' ? tr('Inconnu de VirusTotal')
    : v.kind === 'malveillant' ? tr('Malveillant : {m} / {n}', { m: v.malicious, n: v.total })
      : v.kind === 'suspect' ? tr('Suspect : {s} / {n}', { s: v.suspicious, n: v.total })
        : tr('Aucune détection : 0 / {n}', { n: v.total })
  return <span className={`pill ${v.tone}`.trim()} data-vt={v.kind}>{label}</span>
}

// État commun à la fiche d'un ticket : la clé de l'utilisateur est-elle enregistrée, quelle recherche est en cours,
// quelle est la dernière erreur. `announce` alimente la zone live de la fiche, `reload` recharge le ticket (les
// recherches enregistrées en font partie). Renvoie null quand la fonction n'existe pas pour cet utilisateur.
export function useVirusTotal(enabled, enc, { announce, reload }) {
  const [configured, setConfigured] = useState(null)   // null : pas encore su
  const [busy, setBusy] = useState(null)               // clé de la recherche en cours (« piece:… », « alerte:… », « saisie »)
  const [failure, setFailure] = useState(null)         // { key, message } | { key, needKey: true }
  const [last, setLast] = useState(null)               // { key, lookup } : dernière recherche aboutie dans cette page
  useEffect(() => {
    if (enabled) api('/me/virustotal').then((r) => setConfigured(r.configured)).catch(() => setConfigured(null))
  }, [enabled])
  if (!enabled) return null
  const lookup = async (key, json) => {
    if (busy) return
    setFailure(null)
    if (configured === false) { setFailure({ key, needKey: true }); return }
    setBusy(key)
    if (key.startsWith('piece:')) announce(tr('Recherche sur VirusTotal en cours…'))
    try {
      const r = await api(`/tickets/${enc}/virustotal`, { method: 'POST', json })
      setLast({ key, lookup: r })
      if (key.startsWith('piece:')) announce(sentence(r))
      await reload()
    } catch (e) {
      setFailure({ key, message: e.message })
    } finally { setBusy(null) }
  }
  return { configured, setConfigured, busy, failure, last, lookup }
}

function NeedKey() {
  return (
    <p className="vt-nokey">{tr("Aucune clé d'API VirusTotal n'est enregistrée pour votre compte.")}{' '}
      <Link to="/profil">{tr('Ajouter ma clé dans mon profil')}</Link></p>
  )
}

// Erreur d'une recherche, au plus près de son déclencheur.
function Failure({ vt, k }) {
  if (vt.failure?.key !== k) return null
  if (vt.failure.needKey) return <div className="error action-status" role="alert"><NeedKey /></div>
  return <p className="error action-status" role="alert">{vt.failure.message}</p>
}

// Ligne d'une pièce du registre des preuves : bouton de recherche, puis dernier résultat connu pour cette pièce.
// L'empreinte n'est pas envoyée par le navigateur : le serveur prend celle de la pièce (pour une image ré-encodée,
// celle du fichier reçu quand elle est connue).
export function VtPieceButton({ vt, a }) {
  if (!vt || a.content_type === 'application/json') return null
  const key = `piece:${a.id}`
  return (
    <button type="button" className="small-btn vt-row-btn" disabled={!!vt.busy} aria-busy={vt.busy === key || undefined}
      aria-label={tr('Chercher l\'empreinte de « {name} » sur VirusTotal', { name: a.filename })}
      onClick={() => vt.lookup(key, { source: 'piece', attachment_id: a.id })}>{tr('VirusTotal')}</button>
  )
}

export function VtPieceState({ vt, a, lookups }) {
  if (!vt) return null
  const key = `piece:${a.id}`
  const l = lastFor(lookups, (x) => x.source_id === a.id)
  return (
    <>
      {vt.busy === key && <p className="muted small vt-row-state">{tr('Recherche sur VirusTotal en cours…')}</p>}
      {vt.busy !== key && l && (
        <p className="small vt-row-state"><VtVerdict l={l} /> <span className="muted">{formatUtc(l.created_at)}
          {l.hash !== a.sha256 ? ` · ${tr('empreinte du fichier reçu, avant ré-encodage')}` : ''}</span></p>
      )}
      <Failure vt={vt} k={key} />
    </>
  )
}

function sourceLabel(l, names) {
  const name = names[l.source_id]
  if (l.source_type === 'piece') return name ? tr('Pièce « {name} »', { name }) : tr('Pièce du ticket')
  if (l.source_type === 'preuve_externe') return name ? tr('Preuve externe « {name} »', { name }) : tr('Preuve externe')
  if (l.source_type === 'alerte') return tr('Alerte Wazuh')
  return tr('Saisie manuelle')
}

function Detail({ l }) {
  const s = l.summary || {}
  const v = verdict(l)
  const link = vtLink(l)
  const st = s.stats || {}
  return (
    <div className="vt-detail">
      <p>{sentence(l)}</p>
      {l.status === 'trouve' && (
        <dl className="kv">
          <dt>{tr('Détections')}</dt>
          <dd>{tr('malveillant {a} · suspect {b} · inoffensif {c} · non détecté {d} (sur {n} moteurs)', { a: v.malicious, b: v.suspicious, c: st.harmless ?? 0, d: st.undetected ?? 0, n: v.total })}</dd>
          <dt>{tr('Dernière analyse')}</dt><dd className="mono small">{formatUtc(s.last_analysis_date)}</dd>
          <dt>{tr('Première soumission')}</dt><dd className="mono small">{formatUtc(s.first_submission_date)}</dd>
          {s.name && <><dt>{tr('Nom du fichier (selon VirusTotal)')}</dt><dd>{s.name}</dd></>}
          {s.type && <><dt>{tr('Type')}</dt><dd>{s.type}</dd></>}
          {Number.isInteger(s.size) && <><dt>{tr('Taille')}</dt><dd className="mono small">{tr('{n} octets', { n: s.size })}</dd></>}
          {s.threat_label && <><dt>{tr('Étiquette de menace suggérée')}</dt><dd className="mono small">{s.threat_label}</dd></>}
          {s.engine_names?.length > 0 && (
            <><dt>{tr('Noms donnés par des moteurs')}</dt>
              <dd><ul className="vt-engines">{s.engine_names.map((e, i) => <li key={i}><span className="muted">{e.engine}</span> <span className="mono small">{e.result}</span></li>)}</ul></dd></>
          )}
          {s.sha256 && s.sha256 !== l.hash && <><dt>{tr('SHA-256 du fichier')}</dt><dd className="mono small vt-hash">{s.sha256}</dd></>}
        </dl>
      )}
      {link && (
        <p><a href={link} target="_blank" rel="noopener noreferrer">{tr('Ouvrir la fiche sur VirusTotal')}<span aria-hidden="true"> ↗</span><span className="sr-only"> {tr('(nouvel onglet)')}</span></a></p>
      )}
    </div>
  )
}

function Item({ l, names, open }) {
  return (
    <li>
      <div className="vt-meta">
        <time className="mono" dateTime={l.created_at}>{formatUtc(l.created_at)}</time>
        <VtVerdict l={l} />
        <span>{sourceLabel(l, names)}</span>
        <span>{tr('par {who}', { who: l.actor })}</span>
      </div>
      <p className="mono small vt-hash">{l.hash_type === 'sha1' ? 'SHA-1' : 'SHA-256'} {l.hash}</p>
      <details open={open || undefined}>
        <summary>{tr('Détail du résultat')}</summary>
        <Detail l={l} />
      </details>
    </li>
  )
}

// Panneau repliable de la fiche : empreintes lues dans les alertes du ticket, saisie manuelle, recherches déjà faites.
// Les empreintes des alertes ne sont demandées au serveur qu'à la première ouverture du panneau (lecture tracée).
export function VirusTotalPanel({ t, enc, vt }) {
  const lookups = t.virustotal?.lookups || []
  const names = Object.fromEntries(t.attachments.map((a) => [a.id, a.filename]))
  const [opened, setOpened] = useState(false)
  const [cands, setCands] = useState(null)            // { alerts } une fois lus
  const [candError, setCandError] = useState('')
  const [value, setValue] = useState('')
  const [invalid, setInvalid] = useState(false)
  const hintId = useId()
  const input = useRef(null)
  const { setConfigured } = vt
  const loadCands = useCallback(() => {
    api(`/tickets/${enc}/virustotal/hashes`).then((r) => { setCands(r); setConfigured(r.configured); setCandError('') }).catch((e) => setCandError(e.message))
  }, [enc, setConfigured])
  useEffect(() => { if (opened) loadCands() }, [opened, loadCands, t.raw_alerts])

  const fromPanel = (k) => k && !k.startsWith('piece:')
  const submit = (e) => {
    e.preventDefault()
    const h = normalizeHash(value)
    if (!isHash(h)) { setInvalid(true); input.current?.focus(); return }
    setInvalid(false)
    vt.lookup('saisie', { source: 'saisie', hash: h })
  }
  const status = fromPanel(vt.busy) ? tr('Recherche sur VirusTotal en cours…')
    : vt.last && fromPanel(vt.last.key) && !vt.failure ? sentence(vt.last.lookup) : ''

  return (
    <Section id="virustotal" title={tr('VirusTotal')} summary={lookups.length ? tr('{n} recherche(s)', { n: lookups.length }) : null} onToggle={(o) => { if (o) setOpened(true) }}>
      <p className="muted small">{ONLY_HASH()} {tr("VirusTotal, service externe, apprend seulement que cette empreinte intéresse quelqu'un. Chaque recherche est inscrite ci-dessous et au journal d'audit ; elle n'est jamais montrée au client.")}</p>
      {vt.configured === false ? <NeedKey /> : (
        <>
          <form className="vt-controls" onSubmit={submit} noValidate>
            <label className="grow">{tr('Empreinte SHA-256 ou SHA-1')}
              <input ref={input} className="mono" value={value} onChange={(e) => { setValue(e.target.value); setInvalid(false) }} spellCheck={false} autoComplete="off"
                maxLength={90} aria-invalid={invalid || undefined} aria-describedby={invalid ? hintId : undefined} />
            </label>
            <button className="dark" disabled={!!vt.busy} aria-busy={vt.busy === 'saisie' || undefined}>{tr('Chercher sur VirusTotal')}</button>
          </form>
          {invalid && <p className="field-error" id={hintId} role="alert">{tr("Empreinte attendue : 64 caractères hexadécimaux (SHA-256) ou 40 (SHA-1). MD5 n'est pas accepté.")}</p>}
          <Failure vt={vt} k="saisie" />
          <h3>{tr('Empreintes relevées dans les alertes du ticket')}</h3>
          {candError && <p className="error" role="alert">{candError}</p>}
          {!cands && !candError && <p className="muted small">{tr('Chargement…')}</p>}
          {cands && cands.alerts.length === 0 && <p className="muted small">{tr("Aucune empreinte SHA-256 ou SHA-1 dans les alertes brutes conservées de ce ticket.")}</p>}
          {cands && cands.alerts.length > 0 && (
            <ul className="vt-cands">
              {cands.alerts.map((c) => {
                const key = `alerte:${c.hash}`
                const done = lastFor(lookups, (x) => x.hash === c.hash)
                return (
                  <li key={c.hash}>
                    <div className="grow">
                      <p className="mono small vt-hash">{c.hash}</p>
                      <p className="muted small vt-hash">{c.hash_type === 'sha1' ? 'SHA-1' : 'SHA-256'} · <span className="mono">{c.field}</span>{c.file ? <> · <span className="mono">{c.file}</span></> : null} {done && <VtVerdict l={done} />}</p>
                      <Failure vt={vt} k={key} />
                    </div>
                    <button type="button" disabled={!!vt.busy} aria-busy={vt.busy === key || undefined}
                      aria-label={tr('Chercher {hash} sur VirusTotal', { hash: shortHash(c.hash) })}
                      onClick={() => vt.lookup(key, { source: 'alerte', hash: c.hash })}>{tr('Chercher')}</button>
                  </li>
                )
              })}
            </ul>
          )}
        </>
      )}
      {/* Zone live toujours présente : l'état d'une recherche lancée d'ici est annoncé sans déplacer le focus. */}
      <p className="live" role="status">{status}</p>
      <h3>{tr('Recherches faites sur ce ticket')}</h3>
      {lookups.length === 0 ? <p className="muted small">{tr("Aucune recherche pour l'instant.")}</p> : (
        <ol className="vt-list" aria-label={tr('Recherches VirusTotal de ce ticket, de la plus récente à la plus ancienne (UTC)')}>
          {lookups.map((l) => <Item key={l.id} l={l} names={names} open={vt.last?.lookup.id === l.id} />)}
        </ol>
      )}
    </Section>
  )
}

// Profil : la clé d'API VirusTotal de l'utilisateur. Elle est chiffrée par le serveur et n'est jamais réaffichée ;
// seul son état (« enregistrée » ou non) est connu de l'interface.
export function VirusTotalKey() {
  const [state, setState] = useState(null)        // { configured, enabled }
  const [error, setError] = useState('')
  const [status, track] = useActionStatus()
  const [ask, dialog] = useConfirm()
  useEffect(() => { api('/me/virustotal').then(setState).catch((e) => setError(e.message)) }, [])
  const save = async (e) => {
    e.preventDefault()
    const form = e.target
    const api_key = new FormData(form).get('api_key').trim()
    const r = await track(() => api('/me/virustotal', { method: 'PUT', json: { api_key } }), state?.configured ? tr('Clé remplacée.') : tr('Clé enregistrée.'))
    if (r) { form.reset(); setState(r) }
  }
  const remove = async () => {
    const r = await ask({
      title: tr('Retirer votre clé VirusTotal ?'),
      body: <p>{tr("Vous ne pourrez plus lancer de recherche sur VirusTotal tant qu'une clé n'est pas enregistrée de nouveau. Les recherches déjà faites restent au registre des tickets.")}</p>,
      confirm: tr('Retirer la clé'), danger: true,
      action: () => api('/me/virustotal', { method: 'DELETE' }),
    })
    if (r) { setState(r.result); track(async () => {}, tr('Clé retirée.')) }
  }
  return (
    <section className="card section vt-key" aria-label={tr('VirusTotal')}>
      <header className="section-head"><h2>{tr('VirusTotal')}</h2></header>
      <p className="muted small">{tr("Votre clé d'API personnelle sert à chercher l'empreinte d'un fichier sur VirusTotal depuis la fiche d'un ticket.")} <strong>{ONLY_HASH()}</strong> {tr("VirusTotal est un service externe : il apprend que cette empreinte intéresse quelqu'un, pas ce que contient le fichier.")}</p>
      {error && <p className="error" role="alert">{error}</p>}
      {state && (
        <>
          <p data-testid="vt-key-state">{state.configured
            ? tr("Une clé est enregistrée (chiffrée). Elle n'est jamais réaffichée.")
            : tr("Aucune clé enregistrée : la recherche sur VirusTotal n'est pas disponible pour votre compte.")}</p>
          <form onSubmit={save} className="row gap wrap">
            <label>{state.configured ? tr('Nouvelle clé d\'API VirusTotal') : tr("Clé d'API VirusTotal")}
              <input name="api_key" type="password" required minLength={32} maxLength={128} autoComplete="off" spellCheck={false} />
            </label>
            <button>{state.configured ? tr('Remplacer la clé') : tr('Enregistrer la clé')}</button>
            {state.configured && <button type="button" className="danger" onClick={remove}>{tr('Retirer la clé')}</button>}
            <ActionStatus state={status} live />
          </form>
          <p className="muted small">{tr("La clé n'est pas essayée à l'enregistrement : une clé refusée par VirusTotal se voit à la première recherche.")}</p>
        </>
      )}
      {dialog}
    </section>
  )
}
