// Contrôle automatisé WCAG 2.x A/AA avec axe-core (n'est qu'une partie d'un audit RGAA : ne remplace pas un audit humain).
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { unfoldAll } from '../harness.mjs'
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')

const PAGES = {
  admin: ['/admin/comptes', '/admin/clients', '/admin/cles', '/admin/mitre', '/admin/revue', '/admin/audit', '/admin/systeme', '/profil'],
  manager: ['/tickets', '/kanban', '/pilotage', '/rapports', '/tickets/ACME-1', '/tickets/ACME-1/rapport', '/mitre', '/audit', '/profil'],
  client: ['/tickets', '/tickets/ACME-1'],
}

export default async ({ BASE, check, login }) => {
  for (const [role, paths] of Object.entries(PAGES)) {
    const page = await login(role)
    for (const path of paths) {
      await page.goto(`${BASE}${path}`)
      await page.waitForTimeout(1200)
      await unfoldAll(page)           // fiche ticket : contrôle de tous les panneaux, pas seulement de ceux ouverts par défaut
      await page.evaluate(axeSource)  // eslint-disable-line
      const res = await page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })).violations
        .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0].target.join(' '), help: v.help })))
      check(res.length === 0, `accessibilité ${role} ${path}${res.length ? ' : ' + JSON.stringify(res) : ''}`)
    }
    await page.context().close()
  }
}
