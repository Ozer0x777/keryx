import { t as tr } from '../i18n.js'
import { useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { api } from '../api.js'
import { useAuth } from '../App.jsx'
import Audit from './admin/Audit.jsx'
import Clients from './admin/Clients.jsx'
import Keys from './admin/Keys.jsx'
import Mitre from './admin/Mitre.jsx'
import Review from './admin/Review.jsx'
import System from './admin/System.jsx'
import Users from './admin/Users.jsx'

const TABS = [['comptes', tr('Comptes')], ['clients', tr('Clients')], ['cles', tr("Clés d'API")], ['mitre', tr('MITRE')],
  ['revue', tr('Revue des comptes')], ['audit', tr("Journal d'audit")], ['systeme', tr('État du système')]]

export default function Admin() {
  const { me } = useAuth()
  const [sys, setSys] = useState(null)
  useEffect(() => { if (me.role === 'admin') api('/admin/system').then(setSys).catch(() => {}) }, [me.role])
  if (me.role !== 'admin') return <p className="error">{tr("Réservé au rôle Admin.")}</p>
  const alerts = sys ? [
    sys.clamav === 'injoignable' || sys.clamav === 'réponse inattendue' ? tr("L'antivirus ClamAV est indisponible : les pièces déposées ne sont pas analysées.") : null,
    sys.notifications_failed_24h > 0 ? `${sys.notifications_failed_24h} notification(s) par courriel en échec ces 24 dernières heures.` : null,
    sys.silent_sources > 0 ? `${sys.silent_sources} source(s) Wazuh muette(s) depuis plus de 24 h.` : null,
    sys.storage?.includes('injoignable') ? tr('Le stockage objet des pièces est injoignable.') : null,
    sys.disk_free_mb != null && sys.disk_free_mb < 500 ? tr('Espace disque faible pour les pièces : {n} Mo libres.', { n: sys.disk_free_mb }) : null,
  ].filter(Boolean) : []
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{tr("Administration")}</h1>
          <p className="muted">{tr("Le rôle Admin n'a pas accès au contenu des tickets (séparation administrateur / opérateur, PDIS IV.3.9).")}</p>
        </div>
      </header>
      {alerts.length > 0 && <div className="banner warn" role="alert"><strong>{tr("À traiter :")}</strong><ul>{alerts.map((a) => <li key={a}>{a}</li>)}</ul></div>}
      <nav className="tabs" aria-label={tr("Sections d'administration")}>
        {TABS.map(([to, label]) => <NavLink key={to} to={`/admin/${to}`} className={({ isActive }) => `tab${isActive ? ' on' : ''}`}>{label}</NavLink>)}
      </nav>
      <Routes>
        <Route path="comptes" element={<Users />} />
        <Route path="clients" element={<Clients />} />
        <Route path="cles" element={<Keys />} />
        <Route path="mitre" element={<Mitre />} />
        <Route path="revue" element={<Review />} />
        <Route path="audit" element={<Audit />} />
        <Route path="systeme" element={<System />} />
        <Route path="*" element={<Navigate to="comptes" replace />} />
      </Routes>
    </>
  )
}
