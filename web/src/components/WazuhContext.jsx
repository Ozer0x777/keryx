import { useState } from 'react'
import { api } from '../api.js'
import { utcClock } from '../dates.js'
import { t as tr } from '../i18n.js'
import { ActionStatus } from './ActionStatus.jsx'
import { useConfirm } from './Confirm.jsx'
import Section from './Section.jsx'

// Contexte Wazuh d'un ticket (ADR-0021) : événements du même agent lus dans l'indexeur autour de l'alerte d'origine.
// Affichage seul : rien n'est enregistré tant que l'analyste ne demande pas « Conserver comme preuve ». Le jeu affiché
// est alors renvoyé tel quel au serveur avec son sceau : c'est exactement ce qui a été lu qui est conservé.
// Les événements sont du texte pur (assaini par le serveur) et rendus comme du texte : jamais de HTML.
const COUNTS = [5, 10, 15]

// Date d'un événement, à la milliseconde, en UTC (les événements d'un agent se suivent à quelques secondes).
const stamp = (e) => (e.timestamp ? `${e.timestamp.replace('T', ' ').replace('Z', '')} UTC` : e.timestamp_brut || '—')
const dataText = (e) => Object.entries(e.data || {}).map(([k, v]) => `${k}=${v}`).join('  ')

function Line({ e, alert }) {
  return (
    <li className={alert ? 'is-alert' : undefined}>
      <div className="wz-meta">
        <time className="mono" dateTime={e.timestamp || undefined}>{stamp(e)}</time>
        {alert && <strong className="pill warn">{tr("Alerte du ticket")}</strong>}
        {e.rule_id && <span className="mono">{tr('règle {id} · niveau {level}', { id: e.rule_id, level: e.rule_level || '?' })}</span>}
        <span>{e.rule_description}</span>
      </div>
      <p className="wz-log">{e.full_log || dataText(e) || '—'}</p>
    </li>
  )
}

export default function WazuhContext({ t, enc, run, open }) {
  const [before, setBefore] = useState(5)
  const [after, setAfter] = useState(5)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [set, setSet] = useState(null)        // { document, sha256, token } : le jeu lu, tel que le serveur l'a scellé
  const [kept, setKept] = useState(null)      // message de conservation du jeu affiché
  const [ask, dialog] = useConfirm()

  const fetchContext = async (ev) => {
    ev.preventDefault()
    setLoading(true); setError(''); setKept(null)
    try { setSet(await api(`/tickets/${enc}/wazuh-context`, { method: 'POST', json: { before, after } })) } catch (e) { setSet(null); setError(e.message) } finally { setLoading(false) }
  }

  const doc = set?.document
  const count = doc ? doc.before.length + doc.after.length : 0
  const keep = async () => {
    const r = await ask({
      title: tr('Conserver ces {n} événements comme preuve de {ref} ?', { n: count, ref: t.ref }),
      body: <>
        <p>{tr("Le jeu affiché est enregistré tel quel au registre des preuves : pièce interne, jamais visible du client, méthode « Extraction indexeur Wazuh », collectée le {when}.", { when: stamp({ timestamp: doc.fetched_at }) })}</p>
        <p>{tr("Empreinte SHA-256 :")} <span className="mono small wz-hash">{set.sha256}</span></p>
        <p>{tr("Elle suit ensuite le même cycle de vie que les autres pièces (téléchargement motivé, restitution, destruction).")}</p>
      </>,
      fields: [{ name: 'description', label: tr('Description (registre de collecte)'), minLength: 3, maxLength: 500,
        initial: tr("Contexte Wazuh de l'alerte : {b} événements avant, {a} après (agent {agent})", { b: doc.before.length, a: doc.after.length, agent: doc.source.agent_id }) }],
      confirm: tr('Conserver comme preuve'),
      action: ({ description }) => run(() => api(`/tickets/${enc}/wazuh-context/keep`, {
        method: 'POST', json: { document: doc, token: set.token, description, sensitivity: t.tlp },
      }), tr('Contexte Wazuh conservé comme preuve.')),
    })
    if (r) setKept({ ok: tr('Conservé au registre des preuves à {h}', { h: utcClock() }) })
  }

  return (
    <Section id="contexte-wazuh" title={tr("Contexte Wazuh")} summary={doc ? tr('{b} avant · {a} après', { b: doc.before.length, a: doc.after.length }) : null}>
      <p className="muted small">{tr("Événements du même agent ({agent}) autour de l'alerte d'origine, lus dans l'indexeur Wazuh. Rien n'est enregistré tant que vous ne conservez pas le jeu comme preuve.", { agent: [t.agent.id, t.agent.name].filter(Boolean).join(' · ') })}</p>
      <form className="wz-controls" onSubmit={fetchContext}>
        <label>{tr("Événements avant l'alerte")}
          <select value={before} onChange={(e) => setBefore(Number(e.target.value))}>{COUNTS.map((n) => <option key={n} value={n}>{n}</option>)}</select>
        </label>
        <label>{tr("Événements après l'alerte")}
          <select value={after} onChange={(e) => setAfter(Number(e.target.value))}>{COUNTS.map((n) => <option key={n} value={n}>{n}</option>)}</select>
        </label>
        <button className="dark" disabled={loading} aria-busy={loading || undefined}>{tr("Récupérer")}</button>
      </form>
      {/* Zone live toujours présente : l'état de la lecture est annoncé sans déplacer le focus. */}
      <p className="live" role="status">{loading
        ? tr("Lecture de l'indexeur Wazuh en cours…")
        : doc ? tr("{b} événement(s) avant et {a} après l'alerte, lus à {h}.", { b: doc.before.length, a: doc.after.length, h: utcClock(new Date(doc.fetched_at)) }) : ''}</p>
      {error && <p className="error" role="alert">{error}</p>}
      {doc && (
        <>
          <ol className="wz-list" aria-label={tr("Événements Wazuh autour de l'alerte, du plus ancien au plus récent (UTC)")}>
            {doc.before.map((e, i) => <Line key={`b${i}`} e={e} />)}
            <Line e={doc.alert_entry} alert />
            {doc.after.map((e, i) => <Line key={`a${i}`} e={e} />)}
          </ol>
          {count === 0 && <p className="muted">{tr("L'indexeur ne contient aucun autre événement de cet agent autour de l'alerte.")}</p>}
          <div className="row gap wrap end">
            <ActionStatus state={kept} />
            {open
              ? <button type="button" className="wz-keep" onClick={keep} disabled={!!kept}>{tr("Conserver comme preuve")}</button>
              : <span className="muted small">{tr("Ticket clos : le jeu peut être consulté, pas conservé.")}</span>}
          </div>
        </>
      )}
      {dialog}
    </Section>
  )
}
