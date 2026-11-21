import { t as tr } from '../i18n.js'
import Mitre from './admin/Mitre.jsx'

// Table MITRE du manager : même panneau que dans l'administration, avec le titre de page qui lui manquait (h1).
export default function MitrePage() {
  return (
    <>
      <header className="page-head"><div><h1>{tr('Table MITRE')}</h1></div></header>
      <Mitre />
    </>
  )
}
