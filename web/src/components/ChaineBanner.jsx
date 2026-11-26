import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { t as tr } from '../i18n.js'
import { formatUtc } from '../labels.js'

// Battement de cœur manquant (ADR-0032) : la chaîne Wazuh vers Keryx d'un client est peut-être coupée, des alertes
// peuvent ne plus arriver. Vérifié à l'ouverture puis chaque minute, pour l'équipe (analyste, manager).
export default function ChaineBanner() {
  const [muets, setMuets] = useState([])
  useEffect(() => {
    let stop = false
    const load = () => api('/battements').then((r) => { if (!stop) setMuets(r.items.filter((x) => x.manquant_depuis)) }).catch(() => {})
    load()
    const id = setInterval(load, 60000)
    return () => { stop = true; clearInterval(id) }
  }, [])
  if (muets.length === 0) return null
  return (
    <div className="banner danger" role="alert" data-testid="chaine-muette">
      <strong>{tr('Chaîne d\u2019alerte muette :')}</strong>{' '}
      {muets.map((x) => tr('{c} (dernier battement : {d})', { c: x.name, d: x.dernier ? formatUtc(x.dernier) : tr('aucun') })).join(' · ')}.{' '}
      {tr('Des alertes Wazuh peuvent ne plus arriver dans Keryx : vérifier le manager, la règle, l\u2019intégration et le réseau.')}
    </div>
  )
}
