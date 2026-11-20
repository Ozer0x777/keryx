import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { api } from './api.js'
import Layout from './components/Layout.jsx'
import Admin from './pages/Admin.jsx'
import Kanban from './pages/Kanban.jsx'
import Login from './pages/Login.jsx'
import Mitre from './pages/admin/Mitre.jsx'
import Profile from './pages/Profile.jsx'
import Ticket from './pages/Ticket.jsx'
import Tickets from './pages/Tickets.jsx'

const AuthContext = createContext(null)
export const useAuth = () => useContext(AuthContext)

export default function App() {
  const [me, setMe] = useState(undefined) // undefined = chargement, null = non connecté
  const navigate = useNavigate()

  const refresh = useCallback(async () => {
    try {
      setMe(await api('/me'))
    } catch {
      setMe(null)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])
  useEffect(() => {
    const onUnauthorized = () => { setMe(null); navigate('/connexion') }
    window.addEventListener('keryx:unauthorized', onUnauthorized)
    return () => window.removeEventListener('keryx:unauthorized', onUnauthorized)
  }, [navigate])

  const logout = async () => {
    try { await api('/auth/logout', { method: 'POST' }) } catch { /* déjà déconnecté */ }
    setMe(null)
    navigate('/connexion')
  }

  if (me === undefined) return <p className="loading">Chargement…</p>
  const home = me?.role === 'admin' ? '/admin' : '/tickets'
  return (
    <AuthContext.Provider value={{ me, refresh, logout }}>
      <Routes>
        <Route path="/connexion" element={me ? <Navigate to={home} replace /> : <Login onDone={refresh} />} />
        <Route element={me ? <Layout /> : <Navigate to="/connexion" replace />}>
          <Route path="/tickets" element={<Tickets />} />
          <Route path="/kanban" element={<Kanban />} />
          <Route path="/tickets/:ref" element={<Ticket />} />
          <Route path="/admin/*" element={<Admin />} />
          <Route path="/mitre" element={<Mitre />} />
          <Route path="/profil" element={<Profile />} />
        </Route>
        <Route path="*" element={<Navigate to={me ? home : '/connexion'} replace />} />
      </Routes>
    </AuthContext.Provider>
  )
}
