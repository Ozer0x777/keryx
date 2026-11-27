// Contrôle automatisé WCAG 2.x A/AA avec axe-core (n'est qu'une partie d'un audit RGAA : ne remplace pas un audit humain).
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { unfoldAll } from '../harness.mjs'
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')

const PAGES = {
  admin: ['/admin/comptes', '/admin/clients', '/admin/cles', '/admin/astreinte', '/admin/mitre', '/admin/revue', '/admin/audit', '/admin/systeme', '/profil'],
  manager: ['/tickets', '/kanban', '/parc?client=ACME', '/pilotage', '/rapports', '/tickets/ACME-1', '/tickets/ACME-1/rapport', '/tickets/ACME-1/rapport-analyse', '/tickets/ACME-1/point-situation', '/mitre', '/politique', '/audit', '/profil'],
  client: ['/tickets', '/parc', '/tickets/ACME-1'],
}

export default async ({ BASE, check, login }) => {
  for (const [role, paths] of Object.entries(PAGES)) {
    const page = await login(role)
    for (const path of paths) {
      await page.goto(`${BASE}${path}`)
      await page.waitForTimeout(1200)
      await unfoldAll(page)           // fiche ticket : contrôle de tous les panneaux, pas seulement de ceux ouverts par défaut
      await page.evaluate(axeSource)  // eslint-disable-line
      await page.evaluate(() => Promise.all(document.getAnimations().filter((a) => a.effect?.getComputedTiming().endTime !== Infinity).map((a) => a.finished.catch(() => {}))))   // fondu d'un dialogue terminé : contraste mesuré sur l'état final
      const res = await page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })).violations
        .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0].target.join(' '), help: v.help })))
      check(res.length === 0, `accessibilité ${role} ${path}${res.length ? ' : ' + JSON.stringify(res) : ''}`)
    }
    // Dialogues ouverts (<dialog> modal) : même contrôle, sur un dialogue de confirmation avec champ et sur le formulaire d'édition d'un compte.
    const opened = role === 'manager' ? ['/tickets', 'Enregistrer ce filtre'] : role === 'admin' ? ['/admin/comptes', /^Modifier le compte/] : null
    if (opened) {
      await page.goto(`${BASE}${opened[0]}`)
      await page.getByRole('button', { name: opened[1] }).first().click()
      await page.locator('dialog[open]').waitFor()
      if (role === 'manager') await page.locator('dialog[open] button[type=submit]').click()   // nom vide : la validation en ligne s'affiche, le dialogue reste ouvert
      await page.waitForTimeout(300)
      if (await page.locator('dialog[open]').count()) {
        await page.evaluate(axeSource)  // eslint-disable-line
        await page.evaluate(() => Promise.all(document.getAnimations().filter((a) => a.effect?.getComputedTiming().endTime !== Infinity).map((a) => a.finished.catch(() => {}))))   // fondu d'un dialogue terminé : contraste mesuré sur l'état final
        const res = await page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })).violations
          .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0].target.join(' '), help: v.help })))
        check(res.length === 0, `accessibilité ${role} : dialogue ouvert sur ${opened[0]}${res.length ? ' : ' + JSON.stringify(res) : ''}`)
        await page.keyboard.press('Escape')
      } else check(false, `accessibilité ${role} : le dialogue attendu s'est fermé avant le contrôle`)
    }
    await page.context().close()
  }
}
