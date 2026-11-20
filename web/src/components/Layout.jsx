import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../App.jsx'
import { ROLES } from '../labels.js'

function Shield() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#5B8DEF" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  )
}

export default function Layout() {
  const { me, logout } = useAuth()
  const initials = me.display_name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()
  const links = me.role === 'admin'
    ? [['/admin', 'Administration']]
    : me.role === 'client'
      ? [['/tickets', 'Mes incidents']]
      : [['/tickets', 'Tickets'], ['/kanban', 'Kanban']]
  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Navigation principale">
        <div className="brand"><Shield /><span>Keryx</span></div>
        <div className="nav-section">{{ client: 'Portail client', admin: 'Administration' }[me.role] || 'Détection'}</div>
        {links.map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>{label}</NavLink>
        ))}
        <div className="sidebar-user">
          <span className="avatar" aria-hidden="true">{initials}</span>
          <span className="who">
            <span className="name">{me.display_name}</span>
            <span className="role">{ROLES[me.role]} · 2FA active</span>
          </span>
        </div>
        <button type="button" className="nav-logout" onClick={logout}>Se déconnecter</button>
      </nav>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
