import { t as tr } from '../i18n.js'
import AuditViewer from '../components/AuditViewer.jsx'

export default function AuditPage() {
  return (
    <>
      <header className="page-head"><div><h1>{tr("Journal d'audit")}</h1><p className="muted">{tr("Entrées relatives à vos clients.")}</p></div></header>
      <AuditViewer />
    </>
  )
}
