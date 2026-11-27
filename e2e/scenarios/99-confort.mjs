import { eventually, unfold } from '../harness.mjs'

// Conforts de l'équipe : fil d'activité unifié, journal brut surligné, file compacte, raccourcis clavier, barre
// collante sans titre en double.
export default async ({ BASE, check, login, stack }) => {
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) }).then((r) => r.json())
  const ref = (await send({ timestamp: new Date().toISOString(), id: 'cf1', rule: { id: '100960', level: 10, description: 'confort : sshd', groups: ['sshd'] }, agent: { id: '070', name: 'srv-confort', ip: '10.20.7.1' }, full_log: 'Nov 28 10:00:00 srv-confort sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2' })).ticket
  const m = await login('analyste')
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector('.ticket-head')
  const hl = await eventually(async () => (await m.locator('.rich-content pre mark.hl-ip', { hasText: '203.0.113.9' }).count()) === 1 && (await m.locator('.rich-content pre mark.hl-user', { hasText: 'admin' }).count()) === 1)
  check(hl, `journal brut : adresse et compte mis en évidence${hl ? '' : ' — ' + (await m.locator('.rich-content pre').evaluateAll((l) => l.map((e) => e.outerHTML.slice(0, 300)).join(' | ')))}`)
  check(await m.locator('.ticket-sticky.head-visible').count() === 1, 'barre collante : pas de titre en double tant que l\'en-tête est visible')
  await unfold(m, 'Commentaires')
  await m.locator('section[aria-label="Commentaires"] .rich-content').last().click()
  await m.keyboard.type('Commentaire pour le fil.')
  await m.locator('section[aria-label="Commentaires"]').getByRole('button', { name: 'Publier' }).click()
  await m.waitForSelector('section[aria-label="Commentaires"] >> text=Commentaire pour le fil.')
  await m.goto(`${BASE}/tickets/${ref}?onglet=preuves`)
  await unfold(m, 'Registre des actions')
  await m.locator('section[aria-label="Registre des actions"]').getByRole('button', { name: 'Tout', exact: true }).click()
  check(await eventually(async () => (await m.locator('section[aria-label="Registre des actions"] .activity-comment').innerText()).includes('Commentaire pour le fil.')), 'activité « Tout » : le commentaire dans le même fil que les actions')
  await m.locator('body').click({ position: { x: 5, y: 5 } })
  await m.keyboard.press('?')
  check(await eventually(async () => (await m.locator('dialog[open] h2', { hasText: 'Raccourcis clavier' }).count()) === 1), 'fiche : « ? » ouvre l\'aide des raccourcis')
  await m.keyboard.press('Escape')
  await m.goto(`${BASE}/tickets`)
  await m.waitForSelector('table.queue tbody tr td.mono a')
  await m.locator('h1').click()
  await m.keyboard.press('j')
  check(await eventually(async () => await m.evaluate(() => document.activeElement?.closest('table.queue') !== null)), 'file : « j » place le focus sur le premier ticket')
  await m.getByRole('button', { name: /Affichage (confortable|compact)/ }).click()
  check(await eventually(async () => (await m.locator('table.queue.compact').count()) === 1), 'file : affichage compact')
  await m.getByRole('button', { name: /Affichage compact/ }).click()
  check(m.errors.length === 0, 'aucune erreur JavaScript')
}
