import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { t } from '../i18n.js'
import { formatUtc } from '../labels.js'

const KINDS = { get assignation() { return t('Ticket affecté') }, get mention() { return t('Vous avez été mentionné') }, get echeance() { return t('Échéance dépassée') }, get reponse_client() { return t('Réponse du client') } }

// Cloche : nombre de notifications non lues (relevé toutes les 60 s) et liste. Référence et nature seulement.
export default function NotificationBell() {
  const [unread, setUnread] = useState(0)
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState([])
  const ref = useRef(null)
  const navigate = useNavigate()

  const count = useCallback(() => api('/notifications/count').then((r) => setUnread(r.unread)).catch(() => {}), [])
  useEffect(() => { count(); const t = setInterval(count, 60000); return () => clearInterval(t) }, [count])
  useEffect(() => {
    if (!open) return undefined
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey) }
  }, [open])

  const toggle = async () => {
    if (!open) { try { const r = await api('/notifications'); setItems(r.items); setUnread(r.unread) } catch { /* silencieux */ } }
    setOpen(!open)
  }
  const go = async (n) => {
    try { await api('/notifications/read', { method: 'POST', json: { ids: [n.id] } }) } catch { /* silencieux */ }
    setOpen(false); count(); navigate(`/tickets/${encodeURIComponent(n.ref)}`)
  }
  const readAll = async () => { try { await api('/notifications/read', { method: 'POST' }); setItems(items.map((n) => ({ ...n, read: true }))); setUnread(0) } catch { /* silencieux */ } }

  return (
    <div className="bell" ref={ref}>
      <button type="button" className="nav-link bell-btn" aria-expanded={open} aria-haspopup="true" onClick={toggle}>
        {t('Notifications')}{unread > 0 && <span className="bell-count" aria-label={`${unread} non lue(s)`}>{unread}</span>}
      </button>
      {open && (
        <div className="bell-panel card" role="region" aria-label="Notifications">
          <div className="row between"><strong>{t('Notifications')}</strong>{unread > 0 && <button type="button" className="link" onClick={readAll}>{t('Tout marquer comme lu')}</button>}</div>
          {items.length === 0 && <p className="muted small">{t('Aucune notification.')}</p>}
          <ul>
            {items.map((n) => (
              <li key={n.id} className={n.read ? '' : 'unread'}>
                <button type="button" onClick={() => go(n)}>
                  <span className="strong">{KINDS[n.kind] || n.kind}</span> · <span className="mono">{n.ref}</span>
                  <span className="muted small">{n.actor ? ` · ${n.actor}` : ''} · {formatUtc(n.ts)}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
