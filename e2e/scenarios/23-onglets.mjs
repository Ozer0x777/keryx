import { unfold, until } from '../harness.mjs'

// Fiche ticket en onglets avec barre fixe (ADR-0026) : clavier, URL, saisie conservée, barre collante, portail client.
export default async ({ stack, BASE, check, login }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const made = await send({ timestamp: '2026-11-23T10:00:00.000+0000', id: 'on1', rule: { id: '5770', level: 10, description: 'sshd: onglets', groups: ['sshd'] }, agent: { id: '041', name: 'srv-onglets', ip: '10.20.1.41' }, full_log: 'x' })
  const ref = made.ticket
  check(!!ref, `alerte ingérée (${ref})`)

  const m = await login('manager')
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector('[role=tablist]')
  const noms = await m.locator('[role=tab]').allInnerTexts()
  check(JSON.stringify(noms.map((x) => x.split('\n')[0].trim())) === JSON.stringify(['Vue générale', 'Investigation', 'Preuves', 'Communication', 'REX']), `cinq onglets (${noms.join(' | ')})`)
  const visibles = () => m.locator('[role=tabpanel]:not([hidden])').evaluateAll((l) => l.map((p) => p.getAttribute('aria-labelledby')))
  check(JSON.stringify(await visibles()) === JSON.stringify(['ticket-tab-general']) && await m.getByRole('tab', { name: 'Vue générale' }).getAttribute('aria-selected') === 'true', 'par défaut : Vue générale seule affichée')
  check(!m.url().includes('onglet'), 'Vue générale : rien dans l\'URL')

  // Souris et URL
  await m.getByRole('tab', { name: /^Preuves/ }).click()
  await m.waitForFunction(() => location.search.includes('onglet=preuves'))
  check(JSON.stringify(await visibles()) === JSON.stringify(['ticket-tab-preuves']) && await m.locator('section[aria-label="Registre des preuves"]').isVisible(), 'onglet Preuves : registre visible, le reste masqué, onglet inscrit dans l\'URL')

  // Clavier : flèches, Fin, Début
  await m.getByRole('tab', { name: /^Preuves/ }).focus()
  await m.keyboard.press('ArrowRight')
  await until(async () => await m.getByRole('tab', { name: /^Communication/ }).getAttribute('aria-selected') === 'true', 'Communication sélectionné')
  check(await m.evaluate(() => document.activeElement.id === 'ticket-tab-communication'), 'flèche droite : onglet suivant activé et focalisé')
  await m.keyboard.press('End')
  await until(async () => await m.getByRole('tab', { name: /^REX/ }).getAttribute('aria-selected') === 'true', 'REX sélectionné')
  check(true, 'Fin : dernier onglet')
  await m.keyboard.press('ArrowRight')
  await until(async () => await m.getByRole('tab', { name: 'Vue générale' }).getAttribute('aria-selected') === 'true', 'Vue générale sélectionné')
  check(true, 'flèche droite sur le dernier : retour au premier')
  await m.keyboard.press('ArrowLeft')
  await until(async () => await m.getByRole('tab', { name: /^REX/ }).getAttribute('aria-selected') === 'true', 'REX sélectionné')
  check(true, 'flèche gauche sur le premier : va au dernier')
  const tabindex = await m.locator('[role=tab]').evaluateAll((l) => l.map((e) => e.tabIndex))
  check(JSON.stringify(tabindex) === JSON.stringify([-1, -1, -1, -1, 0]), 'un seul onglet dans l\'ordre de tabulation')
  await m.keyboard.press('Home')
  await m.waitForFunction(() => !location.search.includes('onglet'))

  // Rechargement et URL abîmée
  await m.goto(`${BASE}/tickets/${ref}?onglet=communication`)
  await m.waitForSelector('[role=tablist]')
  check(await m.getByRole('tab', { name: /^Communication/ }).getAttribute('aria-selected') === 'true', 'rechargement : l\'onglet de l\'URL est retrouvé')
  await m.goto(`${BASE}/tickets/${ref}?onglet=nimporte`)
  await m.waitForSelector('[role=tablist]')
  check(await m.getByRole('tab', { name: 'Vue générale' }).getAttribute('aria-selected') === 'true', 'onglet inconnu : retour à la Vue générale')

  // Une saisie n'est pas perdue en changeant d'onglet, et l'onglet porte un repère
  await unfold(m, 'Commentaires')   // active l'onglet Communication et déplie le panneau
  await m.locator('section[aria-label="Commentaires"] .rich-content').last().click()
  await m.keyboard.type('Saisie à conserver.')
  await m.getByRole('tab', { name: /^Preuves/ }).click()
  check(await m.locator('#ticket-tab-communication .unsaved-dot').count() === 1 && (await m.locator('#ticket-tab-communication .unsaved-dot').innerText()).includes('non enregistrées'), 'saisie en cours : repère sur l\'onglet Communication, texte pour les lecteurs d\'écran')
  check((await m.locator('.head-status .unsaved-summary').innerText()).includes('commentaire'), 'saisie en cours : résumé dans la barre fixe depuis un autre onglet')
  await m.getByRole('tab', { name: /^Communication/ }).click()
  check((await m.locator('section[aria-label="Commentaires"] .rich-content').last().innerText()).includes('Saisie à conserver.'), 'saisie conservée au retour sur l\'onglet')

  // Barre fixe : collée en haut de l'écran quand la page défile
  await m.evaluate(() => { const s = document.createElement('div'); s.id = 'e2e-espace'; s.style.height = '3000px'; document.querySelector('.content, main').appendChild(s); window.scrollTo(0, 800) })
  check(await m.locator('.ticket-sticky').evaluate((e) => getComputedStyle(e).position) === 'sticky', 'barre fixe : position collante')
  check(await m.locator('.ticket-sticky').evaluate((e) => Math.round(e.getBoundingClientRect().top)) === 0 && await m.locator('.ticket-steps button').first().isVisible(), 'barre fixe : en haut de l\'écran après défilement, boutons d\'étape atteignables')
  await m.evaluate(() => document.getElementById('e2e-espace').remove())
  await m.context().close()

  // Portail client : page unique, sans onglets
  const c = await login('client')
  await c.goto(`${BASE}/tickets/${ref}`)
  await c.waitForSelector('.ticket-head')
  check(await c.locator('[role=tablist]').count() === 0 && await c.locator('.ticket-sticky').count() === 0, 'portail client : pas d\'onglets ni de barre fixe')
  await c.context().close()
}
