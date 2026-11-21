// Mise en page à plusieurs largeurs : aucune page ne doit déborder horizontalement (hors tableaux défilables).
import { unfoldAll } from '../harness.mjs'

const PAGES = {
  manager: ['/tickets', '/kanban', '/pilotage', '/rapports', '/tickets/ACME-1', '/mitre', '/audit', '/profil'],
  admin: ['/admin/comptes', '/admin/clients', '/admin/cles', '/admin/mitre', '/admin/revue', '/admin/audit', '/admin/systeme'],
  client: ['/tickets', '/tickets/ACME-1'],
}
export default async ({ BASE, check, login }) => {
  for (const [role, paths] of Object.entries(PAGES)) {
    const p = await login(role)
    for (const width of [1024, 768, 390]) {
      await p.setViewportSize({ width, height: 800 })
      const bad = []
      for (const path of paths) {
        await p.goto(`${BASE}${path}`); await p.waitForTimeout(700)
        await unfoldAll(p)   // fiche ticket : tous les panneaux dépliés, pour mesurer tout le contenu
        const over = await p.evaluate(() => {
          const d = document.documentElement
          const wide = [...document.querySelectorAll('main *, .content *')].filter((e) => {
            const r = e.getBoundingClientRect(); if (!r.width) return false
            if (e.closest('.table-wrap, .kanban, pre, .rich-content, .tabs, .barlist')) return false
            return r.right > window.innerWidth + 1 || r.left < -1
          }).slice(0, 2).map((e) => `${e.tagName.toLowerCase()}.${(e.className || '').toString().split(' ')[0]}`)
          return { x: d.scrollWidth - window.innerWidth, wide }
        })
        if (over.x > 1 || over.wide.length) bad.push(`${path} (+${over.x}px ${over.wide.join(',')})`)
      }
      check(bad.length === 0, `${role} à ${width}px : aucun débordement horizontal${bad.length ? ' — ' + bad.join(' ; ') : ''}`)
    }
    await p.context().close()
  }
}
