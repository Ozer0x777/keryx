import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { Navigate, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import { api } from './api.js'
import { t } from './i18n.js'
import { setModeDates } from './labels.js'
import Layout from './components/Layout.jsx'
import { useConfirm } from './components/Confirm.jsx'
import { clearDrafts, disableLeaveGuard, unsavedLabels } from './components/Unsaved.jsx'
import Admin from './pages/Admin.jsx'
import AuditPage from './pages/AuditPage.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Kanban from './pages/Kanban.jsx'
import Login from './pages/Login.jsx'
import MitrePage from './pages/MitrePage.jsx'
import Politique from './pages/Politique.jsx'
import Parc from './pages/Parc.jsx'
import Profile from './pages/Profile.jsx'
import Reports from './pages/Reports.jsx'
import Ticket from './pages/Ticket.jsx'
import TicketReport from './pages/TicketReport.jsx'
import RapportAnalyse from './pages/RapportAnalyse.jsx'
import PointSituation from './pages/PointSituation.jsx'
import Tickets from './pages/Tickets.jsx'

const AuthContext = createContext(null)

// Fiche ticket remontée à chaque changement de référence : aucune saisie (commentaire, qualification, synthèse) ni
// brouillon d'un ticket ne peut passer sur un autre ticket.
function TicketRoute() {
  const { ref } = useParams()
  return <Ticket key={ref} />
}
export const useAuth = () => useContext(AuthContext)

export default function App() {
  const [me, setMe] = useState(undefined) // undefined = chargement, null = non connecté
  const navigate = useNavigate()

  const refresh = useCallback(async () => {
    try {
      const m = await api('/me')
      clearDrafts(m.username)   // un autre compte se connecte dans cet onglet : les brouillons du précédent disparaissent
      setMe(m)
    } catch {
      setMe(null)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])
  useEffect(() => {
    // Session expirée : les brouillons de commentaire restent (leur clé porte l'identifiant du compte), ils seront
    // retrouvés à la reconnexion du même compte. Rien ne peut plus être enregistré : le garde-fou est coupé.
    const onUnauthorized = () => { disableLeaveGuard(); setMe(null); navigate('/connexion') }
    window.addEventListener('keryx:unauthorized', onUnauthorized)
    return () => window.removeEventListener('keryx:unauthorized', onUnauthorized)
  }, [navigate])

  const [ask, dialog] = useConfirm()
  const logout = async () => {
    // Saisies en cours : la question est posée AVANT de fermer la session (après, il serait trop tard pour rester).
    const zones = unsavedLabels()
    if (zones.length) {
      const r = await ask({
        title: t('Se déconnecter sans enregistrer ?'),
        body: <p>{t("Saisies non enregistrées dans le ticket : {zones}. Elles seront perdues, brouillons de commentaire compris.", { zones: zones.join(', ') })}</p>,
        confirm: t('Se déconnecter sans enregistrer'), cancel: t('Rester connecté'), danger: true,
      })
      if (!r) return
    }
    disableLeaveGuard()   // sortie confirmée : ni blocage interne ni « Quitter le site ? » du navigateur
    let target = null
    try { target = (await api('/auth/logout', { method: 'POST' })).redirect } catch { /* déjà déconnecté */ }
    clearDrafts()   // déconnexion explicite : les brouillons de commentaires ne survivent pas
    setMe(null)
    if (target) { window.location.assign(target); return }  // déconnexion unique : le fournisseur d'identité ferme aussi sa session
    navigate('/connexion')
  }

  if (me === undefined) return <p className="loading">{t('Chargement…')}</p>
  setModeDates(me?.role === 'client' ? 'local' : 'utc')   // heure locale pour le client, UTC pour l'équipe
  const home = me?.role === 'admin' ? '/admin' : '/tickets'
  return (
    <AuthContext.Provider value={{ me, refresh, logout }}>
      {dialog}
      <Routes>
        <Route path="/connexion" element={me ? <Navigate to={home} replace /> : <Login onDone={refresh} />} />
        <Route element={me ? <Layout /> : <Navigate to="/connexion" replace />}>
          <Route path="/tickets" element={<Tickets />} />
          <Route path="/kanban" element={<Kanban />} />
          <Route path="/parc" element={<Parc />} />
          <Route path="/tickets/:ref" element={<TicketRoute />} />
          <Route path="/tickets/:ref/rapport" element={<TicketReport />} />
          <Route path="/tickets/:ref/rapport-analyse" element={<RapportAnalyse />} />
          <Route path="/tickets/:ref/point-situation" element={<PointSituation />} />
          <Route path="/admin/*" element={<Admin />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/politique" element={<Politique />} />
          <Route path="/pilotage" element={<Dashboard />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/rapports" element={<Reports />} />
          <Route path="/profil" element={<Profile />} />
        </Route>
        <Route path="*" element={<Navigate to={me ? home : '/connexion'} replace />} />
      </Routes>
    </AuthContext.Provider>
  )
}
