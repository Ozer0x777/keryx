import { useEffect } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../App.jsx'
import { t, t as tr } from '../i18n.js'
import { ROLES } from '../labels.js'
import NotificationBell from './NotificationBell.jsx'

function Shield() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#5B8DEF" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  )
}

// Titre de page propre à chaque écran (RGAA 8.5) : « Écran — Keryx ».
const TITLES = [
  [/^\/tickets\/[^/]+\/rapport/, "Rapport d'incident"], [/^\/tickets\/[^/]+/, 'Ticket'], [/^\/tickets/, 'Tickets'], [/^\/kanban/, 'Kanban'],
  [/^\/pilotage/, 'Pilotage'], [/^\/rapports/, 'Rapports'], [/^\/mitre/, 'Table MITRE'], [/^\/audit/, "Journal d'audit"], [/^\/profil/, 'Mon profil'],
  [/^\/admin\/comptes/, 'Comptes'], [/^\/admin\/clients/, 'Clients'], [/^\/admin\/cles/, "Clés d'API"], [/^\/admin\/mitre/, 'MITRE'],
  [/^\/admin\/revue/, 'Revue des comptes'], [/^\/admin\/audit/, "Journal d'audit"], [/^\/admin\/systeme/, 'État du système'], [/^\/admin/, 'Administration'],
]

export default function Layout() {
  const { pathname } = useLocation()
  useEffect(() => {
    const hit = TITLES.find(([re]) => re.test(pathname))
    document.title = hit ? `${t(hit[1])} — Keryx` : 'Keryx'
  }, [pathname])
  const { me, logout } = useAuth()
  const initials = me.display_name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()
  const links = me.role === 'admin'
    ? [['/admin', t('Administration')]]
    : me.role === 'client'
      ? [['/tickets', t('Mes incidents')]]
      : [['/tickets', t('Tickets')], ['/kanban', t('Kanban')], ['/pilotage', t('Pilotage')], ['/rapports', t('Rapports')], ...(me.role === 'manager' ? [['/mitre', t('Table MITRE')], ['/audit', t("Journal d'audit")]] : [])]
  return (
    <div className="shell">
      <a className="skip" href="#contenu">{t('Aller au contenu')}</a>
      <nav className="sidebar" aria-label={t('Navigation principale')}>
        <div className="brand"><Shield /><span>{tr("Keryx")}</span></div>
        <div className="nav-section">{{ client: t('Portail client'), admin: t('Administration') }[me.role] || t('Détection')}</div>
        {links.map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>{label}</NavLink>
        ))}
        {me.role !== 'admin' && <NotificationBell />}
        <NavLink to="/profil" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>{t('Mon profil')}</NavLink>
        <div className="sidebar-user">
          <span className="avatar" aria-hidden="true">{initials}</span>
          <span className="who">
            <span className="name">{me.display_name}</span>
            <span className="role">{ROLES[me.role]} · {t('2FA active')}</span>
          </span>
        </div>
        <button type="button" className="nav-logout" onClick={logout}>{t('Se déconnecter')}</button>
      </nav>
      <main className="content" id="contenu" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  )
}
