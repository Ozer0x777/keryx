import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../App.jsx'
import { t, t as tr } from '../i18n.js'
import { ROLES } from '../labels.js'
import NotificationBell from './NotificationBell.jsx'
import ChaineBanner from './ChaineBanner.jsx'
import Logo from './Logo.jsx'

function Shield() {
  return <Logo size={30} />
}

// Titre de page propre à chaque écran (RGAA 8.5) : « Écran — Keryx ».
const TITLES = [
  [/^\/tickets\/[^/]+\/rapport-analyse/, "Rapport d'analyse"], [/^\/tickets\/[^/]+\/point-situation/, 'Point de situation'], [/^\/tickets\/[^/]+\/rapport/, "Rapport d'incident"], [/^\/tickets\/[^/]+/, 'Ticket'], [/^\/tickets/, 'Tickets'], [/^\/kanban/, 'Kanban'],
  [/^\/pilotage/, 'Pilotage'], [/^\/rapports/, 'Rapports'], [/^\/politique/, 'Politique des clients'], [/^\/mitre/, 'Table MITRE'], [/^\/audit/, "Journal d'audit"], [/^\/profil/, 'Mon profil'],
  [/^\/admin\/comptes/, 'Comptes'], [/^\/admin\/clients/, 'Clients'], [/^\/admin\/cles/, "Clés d'API"], [/^\/admin\/astreinte/, "Canaux d'astreinte"], [/^\/admin\/mitre/, 'MITRE'],
  [/^\/admin\/revue/, 'Revue des comptes'], [/^\/admin\/audit/, "Journal d'audit"], [/^\/admin\/systeme/, 'État du système'], [/^\/admin/, 'Administration'],
]

export default function Layout() {
  const { pathname } = useLocation()
  // Téléphone : la navigation est repliée derrière un bouton « Menu » et se referme à chaque changement de page.
  const [menuOpen, setMenuOpen] = useState(false)
  useEffect(() => { setMenuOpen(false) }, [pathname])
  useEffect(() => {
    const hit = TITLES.find(([re]) => re.test(pathname))
    document.title = hit ? `${t(hit[1])} — Keryx` : 'Keryx'
  }, [pathname])
  const { me, logout } = useAuth()
  const initials = me.display_name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()
  const links = me.role === 'admin'
    ? [['/admin', t('Administration')]]
    : me.role === 'client'
      ? [['/tickets', t('Mes incidents')], ['/parc', t('Mon parc')]]
      : [['/tickets', t('Tickets')], ['/kanban', t('Kanban')], ['/parc', t('Parc Wazuh')], ['/pilotage', t('Pilotage')], ['/rapports', t('Rapports')], ...(me.role === 'manager' ? [['/politique', t('Politique des clients')], ['/mitre', t('Table MITRE')], ['/audit', t("Journal d'audit")]] : [])]
  return (
    <div className="shell">
      <a className="skip" href="#contenu">{t('Aller au contenu')}</a>
      <nav className={`sidebar${menuOpen ? ' menu-open' : ''}`} aria-label={t('Navigation principale')}>
        <div className="brand"><Shield /><span>{tr("Keryx")}</span></div>
        {me.role !== 'admin' && <NotificationBell />}
        <button type="button" className="menu-toggle" aria-expanded={menuOpen} aria-controls="nav-body" onClick={() => setMenuOpen(!menuOpen)}>
          {menuOpen ? t('Fermer') : t('Menu')}
        </button>
        <div className="nav-body" id="nav-body">
          <div className="nav-section">{{ client: t('Portail client'), admin: t('Administration') }[me.role] || t('Détection')}</div>
          {links.map(([to, label]) => (
            <NavLink key={to} to={to} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>{label}</NavLink>
          ))}
          <NavLink to="/profil" className={({ isActive }) => `nav-link nav-profile${isActive ? ' active' : ''}`}>{t('Mon profil')}</NavLink>
          <div className="sidebar-user">
            <span className="avatar" aria-hidden="true">{initials}</span>
            <span className="who">
              <span className="name">{me.display_name}</span>
              <span className="role">{ROLES[me.role]} · {me.sso ? t('Session SSO') : t('2FA active')}</span>
            </span>
          </div>
          <button type="button" className="nav-logout" onClick={logout}>{t('Se déconnecter')}</button>
        </div>
      </nav>
      <main className="content" id="contenu" tabIndex={-1}>
        {(me.role === 'analyst' || me.role === 'manager') && <ChaineBanner />}
        <Outlet />
      </main>
    </div>
  )
}
