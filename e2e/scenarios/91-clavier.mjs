// Accessibilité au clavier et repères (RGAA 8.5 titres de page, 12.7 lien d'évitement, 7.3 clavier, 10.7 focus visible).
export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  const titles = {}
  for (const path of ['/tickets', '/kanban', '/pilotage', '/rapports', '/mitre', '/profil', '/tickets/ACME-1']) {
    await m.goto(`${BASE}${path}`); await m.waitForTimeout(500)
    titles[path] = await m.title()
  }
  const distinct = new Set(Object.values(titles))
  check(distinct.size === Object.keys(titles).length && Object.values(titles).every((t) => t.endsWith('— Keryx')), `titre de page distinct sur chaque écran (${[...distinct].slice(0, 4).join(' | ')}…)`)

  await m.goto(`${BASE}/tickets`); await m.waitForSelector('tbody tr')
  await m.keyboard.press('Tab')
  const first = await m.evaluate(() => ({ text: document.activeElement.textContent.trim(), cls: document.activeElement.className }))
  check(first.cls.includes('skip'), `premier arrêt clavier : lien d'évitement (« ${first.text} »)`)
  const box = await m.evaluate(() => { const r = document.activeElement.getBoundingClientRect(); return { top: r.top, h: r.height } })
  check(box.top >= 0 && box.h > 20, "le lien d'évitement devient visible au focus")
  await m.keyboard.press('Enter')
  check(await m.evaluate(() => document.activeElement.id === 'contenu'), "le lien d'évitement place le focus sur le contenu principal")

  // Focus visible sur chaque arrêt, aucun piège clavier
  for (const path of ['/tickets', '/tickets/ACME-1', '/profil']) {
    await m.goto(`${BASE}${path}`); await m.waitForTimeout(800)
    const seen = new Set(); const bad = []
    for (let i = 0; i < 45; i++) {
      await m.keyboard.press('Tab')
      const info = await m.evaluate(() => {
        const e = document.activeElement
        if (!e || e === document.body) return null
        const cs = getComputedStyle(e)
        const visibleFocus = (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) || cs.boxShadow !== 'none' || e.matches('input, select, textarea') || e.closest('.tool')
        const r = e.getBoundingClientRect()
        return { id: `${e.tagName}:${(e.getAttribute('aria-label') || e.textContent || e.name || '').trim().slice(0, 25)}`, visibleFocus: !!visibleFocus, onScreen: r.width > 0 && r.height > 0 }
      })
      if (!info) continue
      seen.add(info.id)
      if (!info.visibleFocus || !info.onScreen) bad.push(info.id)
    }
    check(bad.length === 0 && seen.size >= 15, `${path} : ${seen.size} arrêts clavier distincts, focus visible partout${bad.length ? ' — sans indicateur : ' + bad.slice(0, 4).join(', ') : ''}`)
  }
  // La cloche s'ouvre et se ferme au clavier
  await m.goto(`${BASE}/tickets`); await m.waitForSelector('tbody tr')
  await m.getByRole('button', { name: /Notifications/ }).focus()
  await m.keyboard.press('Enter'); await m.waitForSelector('.bell-panel')
  await m.keyboard.press('Escape')
  check(await m.locator('.bell-panel').count() === 0, 'la cloche de notifications se ferme avec Échap')
  await m.context().close()
}
