import AuditViewer from '../components/AuditViewer.jsx'

export default function AuditPage() {
  return (
    <>
      <header className="page-head"><div><h1>Journal d'audit</h1><p className="muted">Entrées relatives à vos clients.</p></div></header>
      <AuditViewer />
    </>
  )
}
