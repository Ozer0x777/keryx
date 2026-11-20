import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from '../App.jsx'
import Audit from './admin/Audit.jsx'
import Clients from './admin/Clients.jsx'
import Keys from './admin/Keys.jsx'
import Mitre from './admin/Mitre.jsx'
import Review from './admin/Review.jsx'
import System from './admin/System.jsx'
import Users from './admin/Users.jsx'

const TABS = [['comptes', 'Comptes'], ['clients', 'Clients'], ['cles', "Clés d'API"], ['mitre', 'MITRE'],
  ['revue', 'Revue des comptes'], ['audit', "Journal d'audit"], ['systeme', 'État du système']]

export default function Admin() {
  const { me } = useAuth()
  if (me.role !== 'admin') return <p className="error">Réservé au rôle Admin.</p>
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Administration</h1>
          <p className="muted">Le rôle Admin n'a pas accès au contenu des tickets (séparation administrateur / opérateur, PDIS IV.3.9).</p>
        </div>
      </header>
      <nav className="tabs" aria-label="Sections d'administration">
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
