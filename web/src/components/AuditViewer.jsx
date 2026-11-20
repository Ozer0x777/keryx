import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { formatUtc } from '../labels.js'

// Journal d'audit consultable. L'Admin ne voit jamais le détail des entrées qui touchent au contenu des tickets.
export default function AuditViewer() {
  const [f, setF] = useState({ actor: '', action: '', client: '', from: '', to: '' })
  const [items, setItems] = useState(null)
  const [next, setNext] = useState(null)
  const [error, setError] = useState('')
  const query = useCallback(async (before) => {
    setError('')
    try {
      const r = await api('/audit/entries', { params: { ...f, before_seq: before, limit: 50 } })
      setItems((cur) => (before ? [...(cur || []), ...r.items] : r.items)); setNext(r.next_before_seq)
    } catch (e) { setError(e.message) }
  }, [f])
  useEffect(() => { query() }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  return (
    <section className="card section" aria-label="Consultation du journal">
      <header className="section-head"><h2>Consulter le journal</h2></header>
      <form className="filters" onSubmit={(e) => { e.preventDefault(); query() }}>
        <label className="filter">Auteur<input value={f.actor} onChange={set('actor')} /></label>
        <label className="filter">Action (début)<input value={f.action} onChange={set('action')} placeholder="ticket." /></label>
        <label className="filter">Client<input value={f.client} onChange={set('client')} placeholder="ACME" /></label>
        <label className="filter">Du<input type="date" value={f.from} onChange={set('from')} /></label>
        <label className="filter">Au<input type="date" value={f.to} onChange={set('to')} /></label>
        <button className="primary" style={{ marginBottom: 10 }}>Filtrer</button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      <div className="table-wrap"><table className="grid">
        <thead><tr><th scope="col" className="num">N°</th><th scope="col">Date</th><th scope="col">Auteur</th><th scope="col">Action</th><th scope="col">Objet</th><th scope="col">Client</th><th scope="col">Détails</th></tr></thead>
        <tbody>
          {items === null && <tr><td colSpan="7" className="muted">Chargement…</td></tr>}
          {items?.length === 0 && <tr><td colSpan="7" className="muted">Aucune entrée.</td></tr>}
          {items?.map((e) => (
            <tr key={e.seq}>
              <td className="num mono small">{e.seq}</td><td className="mono small">{formatUtc(e.ts)}</td><td>{e.actor}</td>
              <td className="mono small">{e.action}</td><td className="mono small">{e.object_id || '—'}</td><td>{e.client || '—'}</td>
              <td className="small">{e.details?.masque ? <span className="pill">masqué (contenu)</span> : <code className="mono">{Object.keys(e.details || {}).length ? JSON.stringify(e.details) : '—'}</code>}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
      {next && <p><button type="button" onClick={() => query(next)}>Charger les entrées plus anciennes</button></p>}
    </section>
  )
}
