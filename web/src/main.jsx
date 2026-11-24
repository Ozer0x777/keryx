import React from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider, useRouteError } from 'react-router-dom'
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import './styles.css'
import App from './App.jsx'
import { initLang, t } from './i18n.js'

initLang()

// Routeur à données : nécessaire à useBlocker (garde-fou « saisies non enregistrées », ADR-0024). Toute l'application
// reste une seule route ; ses <Routes> internes sont inchangés.
// Erreur de rendu : page sobre et traduite, sans pile technique (celle-ci reste dans la console du navigateur).
function RouteError() {
  const error = useRouteError()
  console.error(error)   // eslint-disable-line no-console
  return (
    <main className="content" role="alert">
      <h1>{t("Une erreur empêche d'afficher cette page.")}</h1>
      <p>{t("Rechargez la page. Si l'erreur revient, signalez-la à l'administrateur avec l'heure à laquelle elle s'est produite.")}</p>
      <p><a href="/tickets">{t('Revenir à la file des tickets')}</a></p>
    </main>
  )
}

const router = createBrowserRouter([{ path: '*', element: <App />, errorElement: <RouteError /> }])

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)
