// Garde-fous de mise en page : pas de débordement horizontal, contrôles de filtre alignés, Kanban entièrement visible.
export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  await m.setViewportSize({ width: 1400, height: 900 })
  await m.goto(`${BASE}/tickets`); await m.waitForSelector('tbody tr')
  const overflow = await m.evaluate(() => { const w = document.querySelector('.table-wrap'); return w.scrollWidth - w.clientWidth })
  check(overflow <= 1, `liste des tickets : aucun défilement horizontal à 1400 px (débordement ${overflow} px)`)
  const bottoms = await m.evaluate(() => [...document.querySelectorAll('.filters input[type=search], .filters select, .filters > .row button')].map((e) => Math.round(e.getBoundingClientRect().bottom)))
  check(Math.max(...bottoms) - Math.min(...bottoms) <= 2, `filtres alignés sur une même ligne (écart ${Math.max(...bottoms) - Math.min(...bottoms)} px)`)
  await m.goto(`${BASE}/kanban`); await m.waitForSelector('.column')
  const kan = await m.evaluate(() => { const k = document.querySelector('.kanban'); return k.scrollWidth - k.clientWidth })
  check(kan <= 1, `Kanban : les cinq colonnes sont visibles (débordement ${kan} px)`)
  const titleAlign = await m.evaluate(() => { const h = document.querySelector('.column-head h2').getBoundingClientRect(); const d = document.querySelector('.column-head .dot').getBoundingClientRect(); return Math.round(h.left - d.right) })
  check(titleAlign >= 0 && titleAlign <= 14, `Kanban : titre de colonne collé à sa pastille (écart ${titleAlign} px)`)
  await m.goto(`${BASE}/profil`); await m.waitForSelector('text=Clés de sécurité')
  const ys = await m.evaluate(() => { const f = document.querySelector('form.row'); return [...f.querySelectorAll('input, button')].map((e) => Math.round(e.getBoundingClientRect().bottom)) })
  check(Math.max(...ys) - Math.min(...ys) <= 2, 'profil : champs et bouton « Ajouter une clé » alignés')
  await m.context().close()
}
