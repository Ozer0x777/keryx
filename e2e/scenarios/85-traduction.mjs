// Couverture de la traduction anglaise : aucun libellé d'interface français ne doit rester sur les écrans principaux.
import { unfoldAll } from '../harness.mjs'

const FRENCH = /\b(Aucun|Aucune|Enregistrer|Chargement|Déposer|Créer|Ajouter|Supprimer|Modifier|Retour|Paramétrer|Fermer|Vérifier|Annuler|Désactiver|Réactiver|Régénérer|Révoquer|Télécharger|Détruire|Restituer|Filtrer|Générer|Simuler|Purger|Historique|Commentaires|Pièces|Synthèse|Nouveau commentaire|Mon profil|Éléments|Échéance|Rapport|Pilotage|Charge)\b/

export default async ({ BASE, check, login }) => {
  const scan = async (p, paths, label) => {
    await p.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
    const leaks = []
    for (const path of paths) {
      await p.goto(`${BASE}${path}`); await p.waitForTimeout(1200)
      await unfoldAll(p)   // les panneaux repliés de la fiche ticket comptent aussi
      const text = await p.locator('main, .content').first().innerText()
      const hit = text.split('\n').filter((l) => FRENCH.test(l)).slice(0, 3)
      if (hit.length) leaks.push(`${path} : ${hit.join(' | ')}`)
    }
    check(leaks.length === 0, `traduction anglaise complète pour ${label}${leaks.length ? ' — reste du français : ' + leaks.join(' ;; ') : ''}`)
  }
  const m = await login('manager')
  await scan(m, ['/tickets', '/kanban', '/pilotage', '/rapports', '/tickets/ACME-1', '/tickets/ACME-1/rapport', '/mitre', '/audit', '/profil'], 'le manager')
  await m.context().close()
  // client : portail et fiche ticket ; formulaires ouverts (états)
  const c = await login('client')
  await scan(c, ['/tickets', '/tickets/ACME-1', '/profil'], 'le client')
  await c.context().close()
  const f = await login('manager')
  await f.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
  await f.goto(`${BASE}/tickets/ACME-1`); await f.waitForSelector('text=Evidence register', { state: 'attached' })
  await unfoldAll(f)
  await f.getByRole('button', { name: /Upload a file/ }).click()
  await f.getByRole('button', { name: 'Declare external evidence' }).click()
  const open = (await f.locator('main, .content').first().innerText()).split('\n').filter((l) => FRENCH.test(l)).slice(0, 3)
  check(open.length === 0, `traduction anglaise : formulaires de preuves ouverts${open.length ? ' — ' + open.join(' | ') : ''}`)
  await f.context().close()
  const a = await login('admin')
  await a.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
  await a.goto(`${BASE}/admin/comptes`); await a.waitForSelector('text=New account'); await a.getByRole('button', { name: 'New account' }).click()
  const form1 = (await a.locator('main, .content').first().innerText()).split('\n').filter((l) => FRENCH.test(l)).slice(0, 3)
  check(form1.length === 0, `traduction anglaise : formulaire de compte ouvert${form1.length ? ' — ' + form1.join(' | ') : ''}`)
  await a.goto(`${BASE}/admin/clients`); await a.getByRole('button', { name: 'Configure' }).first().click()
  const forms = (await a.locator('main, .content').first().innerText()).split('\n').filter((l) => FRENCH.test(l)).slice(0, 3)
  check(forms.length === 0, `traduction anglaise : éditeur de client ouvert${forms.length ? ' — ' + forms.join(' | ') : ''}`)
  await scan(a, ['/admin/comptes', '/admin/clients', '/admin/cles', '/admin/mitre', '/admin/revue', '/admin/audit', '/admin/systeme'], "l'admin")
  await a.context().close()
}
