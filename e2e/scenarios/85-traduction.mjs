// Couverture de la traduction anglaise : aucun libellé d'interface français ne doit rester sur les écrans principaux.
const FRENCH = /\b(Aucun|Aucune|Enregistrer|Chargement|Déposer|Créer|Ajouter|Supprimer|Modifier|Retour|Paramétrer|Fermer|Vérifier|Annuler|Désactiver|Réactiver|Régénérer|Révoquer|Télécharger|Détruire|Restituer|Filtrer|Générer|Simuler|Purger|Historique|Commentaires|Pièces|Synthèse|Nouveau commentaire|Mon profil|Éléments|Échéance|Rapport|Pilotage|Charge)\b/

export default async ({ BASE, check, login }) => {
  const scan = async (p, paths, label) => {
    await p.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
    const leaks = []
    for (const path of paths) {
      await p.goto(`${BASE}${path}`); await p.waitForTimeout(1200)
      const text = await p.locator('main, .content').first().innerText()
      const hit = text.split('\n').filter((l) => FRENCH.test(l)).slice(0, 3)
      if (hit.length) leaks.push(`${path} : ${hit.join(' | ')}`)
    }
    check(leaks.length === 0, `traduction anglaise complète pour ${label}${leaks.length ? ' — reste du français : ' + leaks.join(' ;; ') : ''}`)
  }
  const m = await login('manager')
  await scan(m, ['/tickets', '/kanban', '/pilotage', '/rapports', '/tickets/ACME-1', '/tickets/ACME-1/rapport', '/mitre', '/audit', '/profil'], 'le manager')
  await m.context().close()
  const a = await login('admin')
  await scan(a, ['/admin/comptes', '/admin/clients', '/admin/cles', '/admin/mitre', '/admin/revue', '/admin/audit', '/admin/systeme'], "l'admin")
  await a.context().close()
}
