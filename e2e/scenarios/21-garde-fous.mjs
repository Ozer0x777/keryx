import { answerDialog, unfold, until } from '../harness.mjs'

// Fiche ticket : saisies non enregistrées (indicateur, garde-fou de sortie, brouillon de commentaire), motif du faux
// positif, confirmations des étapes qui engagent le client (ADR-0024).
export default async ({ stack, BASE, check, login }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const base = { timestamp: '2026-11-21T09:00:00.000+0000', rule: { id: '5760', level: 10, description: 'sshd: garde-fous', groups: ['sshd'] }, agent: { id: '005', name: 'srv-garde', ip: '10.20.1.17' }, full_log: 'x' }
  const made = await send({ ...base, id: 'gf1' })
  const ref = made.ref || made.ticket || made.ticket_ref
  check(!!ref, `alerte ingérée (${ref})`)

  const m = await login('manager')
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector('.ticket-head')
  await unfold(m, 'Commentaires')

  // Saisie d'un commentaire : indicateur dans l'en-tête, puis garde-fou à la sortie
  await m.locator('section[aria-label="Commentaires"] .rich-content').last().click()
  await m.keyboard.type('Brouillon à ne pas perdre.')
  await m.waitForSelector('.head-status .unsaved-summary')
  check((await m.locator('.head-status .unsaved-summary').innerText()).includes('commentaire'), 'saisie : l\'en-tête annonce un commentaire non enregistré')
  check(await m.locator('section[aria-label="Commentaires"] .unsaved-badge').count() === 1, 'saisie : pastille « Modifications non enregistrées » sur la zone')
  await m.getByRole('link', { name: 'Tickets', exact: true }).first().click()
  const d = m.locator('dialog[open]'); await d.waitFor()
  check((await d.locator('h2').innerText()).includes('sans enregistrer'), 'sortie : le garde-fou demande confirmation')
  await d.locator('button[data-cancel]').click(); await d.waitFor({ state: 'detached' })
  check(m.url().includes(`/tickets/${ref}`), 'sortie : « Rester sur la page » garde la fiche')

  // Brouillon : survit à un rechargement de la page (sessionStorage), retiré à la publication
  const browserDialogs = []
  m.on('dialog', (x) => { browserDialogs.push(x.type()); x.accept() })    // beforeunload au rechargement
  await m.reload()
  await m.waitForSelector('.ticket-head')
  await unfold(m, 'Commentaires')
  check(browserDialogs.includes('beforeunload'), 'rechargement avec une saisie : le navigateur demande confirmation (beforeunload)')
  await m.waitForSelector('text=Brouillon retrouvé')
  check((await m.locator('section[aria-label="Commentaires"] .rich-content').last().innerText()).includes('Brouillon à ne pas perdre.'), 'brouillon : le commentaire est retrouvé après rechargement')

  // Commentaire visible par le client : confirmation qui nomme le client, annulable
  await m.getByLabel('Visible par le client').check()
  await m.getByRole('button', { name: 'Publier', exact: true }).click()
  const c = m.locator('dialog[open]'); await c.waitFor()
  check((await c.locator('h2').innerText()).includes('Acme Industrie') && (await c.locator('button[type=submit]').innerText()).includes('Publier au client Acme Industrie'), 'commentaire visible : confirmation nommant le client')
  await c.locator('button[data-cancel]').click(); await c.waitFor({ state: 'detached' })
  await m.waitForTimeout(1500)   // une publication partie par erreur aurait eu le temps d'apparaître
  check(await m.locator('.comment').count() === 0, 'commentaire visible : annuler ne publie rien')
  await m.getByLabel('Visible par le client').uncheck()
  await m.getByRole('button', { name: 'Publier', exact: true }).click()   // interne : aucune confirmation
  await m.waitForSelector('.comment.internal')
  await until(async () => (await m.locator('.head-status .unsaved-summary').innerText()) === '', 'résumé vide')
  check(true, 'publication : plus de saisie en attente, brouillon vidé')
  check(await m.evaluate((r) => !Object.keys(sessionStorage).some((k) => k.endsWith(`:${r}`)), ref), 'publication : le brouillon est effacé du stockage')

  // Étapes : confirmation explicite de « En réponse », qui nomme le client
  await m.getByRole('button', { name: /→ En évaluation/ }).click()
  await m.waitForSelector('.ticket-head .status:has-text("En évaluation")')
  await m.getByRole('button', { name: /→ En réponse/ }).click()
  const e = m.locator('dialog[open]'); await e.waitFor()
  check((await e.locator('h2').innerText()).includes('En réponse') && (await e.locator('.dialog-body').innerText()).includes('Acme'), 'étape : confirmation de « En réponse » qui nomme le client')
  await e.locator('button[data-cancel]').click(); await e.waitFor({ state: 'detached' })
  check((await m.locator('.ticket-head .status').innerText()).includes('En évaluation'), 'étape : annuler ne change pas le statut')

  // Faux positif : motif obligatoire, 10 caractères au moins
  await m.getByRole('button', { name: /→ Faux positif/ }).click()
  const f = await answerDialog(m, { reason: 'court' }, { stays: true })
  check((await f.locator('.field-error').innerText()).includes('au moins 10'), 'faux positif : motif trop court refusé sous le champ')
  await f.locator('button[data-cancel]').click(); await f.waitFor({ state: 'detached' })

  // Nouvelles zones suivies : MITRE et ajout de lien (onglets Investigation et Vue générale)
  await unfold(m, 'MITRE ATT&CK')
  const mitre = m.locator('section[aria-label="MITRE ATT&CK"]').getByLabel('Techniques (ex. T1110, T1543.003)')
  await mitre.fill('T1110')
  await m.waitForSelector('#ticket-tab-investigation .unsaved-dot')
  check((await m.locator('.head-status .unsaved-summary').innerText()).includes('MITRE'), 'MITRE modifié : repère sur l\'onglet Investigation et résumé dans la barre')
  await mitre.fill('')
  await until(async () => (await m.locator('#ticket-tab-investigation .unsaved-dot').count()) === 0, 'MITRE revenu à l\'état enregistré')
  check(true, 'MITRE remis à l\'état enregistré : plus de repère')

  // Changement de ticket par un lien de la fiche (même composant de route) : la saisie d'un ticket ne passe pas sur l'autre
  const autre = (await send({ ...base, id: 'gf2', rule: { ...base.rule, id: '5761' }, agent: { id: '006', name: 'srv-garde-2', ip: '10.20.1.18' } })).ticket
  await unfold(m, 'Tickets liés')
  await m.fill('section[aria-label="Tickets liés"] input[placeholder="ACME-2"]', autre)
  await m.getByRole('button', { name: 'Lier', exact: true }).click()
  await m.waitForSelector(`.linklist >> text=${autre}`)
  await unfold(m, 'Commentaires')
  await m.locator('section[aria-label="Commentaires"] .rich-content').last().click()
  await m.keyboard.type('Réservé au premier ticket.')
  await m.getByRole('tab', { name: 'Vue générale' }).click()
  await m.locator(`.linklist a:has-text("${autre}")`).click()
  await answerDialog(m)                                   // « Quitter sans enregistrer »
  await m.waitForURL(new RegExp(`/tickets/${autre}`))
  await m.waitForSelector('[role=tablist]')
  await unfold(m, 'Commentaires')
  check(!(await m.locator('section[aria-label="Commentaires"] .rich-content').last().innerText()).includes('Réservé au premier ticket.')
    && (await m.locator('.head-status .unsaved-summary').innerText()) === '', 'lien vers un autre ticket : fiche neuve, aucune saisie héritée')
  await m.goto(`${BASE}/tickets/${ref}?onglet=communication`)
  await unfold(m, 'Commentaires')
  await m.waitForSelector('text=Brouillon retrouvé')
  check((await m.locator('section[aria-label="Commentaires"] .rich-content').last().innerText()).includes('Réservé au premier ticket.'), 'le brouillon reste attaché à son ticket')

  // Déconnexion avec une saisie : question posée avant de fermer la session ; « Rester connecté » garde tout
  await m.locator('section[aria-label="Commentaires"] .rich-content').last().click()
  await m.keyboard.type('Avant déconnexion.')
  await m.getByRole('button', { name: 'Se déconnecter' }).click()
  const q = m.locator('dialog[open]'); await q.waitFor()
  check((await q.locator('h2').innerText()).includes('Se déconnecter sans enregistrer'), 'déconnexion : confirmation demandée s\'il reste une saisie')
  await q.locator('button[data-cancel]').click(); await q.waitFor({ state: 'detached' })
  check((await m.request.get(`${BASE}/api/v1/me`)).status() === 200, 'déconnexion annulée : la session est toujours ouverte')
  const before = browserDialogs.length
  await m.getByRole('button', { name: 'Se déconnecter' }).click()
  await answerDialog(m)
  await m.waitForURL(/connexion/)
  check(browserDialogs.length === before, 'déconnexion confirmée : aucune seconde alerte du navigateur')
  check(await m.evaluate(() => !Object.keys(sessionStorage).some((k) => k.startsWith('keryx:brouillon:'))), 'déconnexion confirmée : brouillons effacés')
  await m.context().close()

  // Kanban : mêmes confirmations que la fiche, motif du faux positif saisissable
  const k = await login('manager')
  const fp = (await send({ ...base, id: 'gf3', rule: { ...base.rule, id: '5762' }, agent: { id: '007', name: 'srv-garde-3', ip: '10.20.1.19' } })).ticket
  await k.goto(`${BASE}/kanban`)
  await k.waitForSelector(`#mv-${fp}`)
  await k.selectOption(`#mv-${fp}`, 'en_evaluation')
  await until(async () => (await k.locator(`section[aria-label="En évaluation"]`).innerText()).includes(fp), 'carte en évaluation')
  await k.goto(`${BASE}/tickets/${fp}`)
  await k.waitForSelector('[role=tablist]')
  await k.locator('section[aria-label="Qualification"] select').first().selectOption('faux_positif')
  await k.locator('section[aria-label="Qualification"] button.primary').click()
  await k.waitForSelector('section[aria-label="Qualification"] .fold-summary:has-text("Faux positif")')
  await k.goto(`${BASE}/kanban`)
  await k.waitForSelector(`#mv-${fp}`)
  await k.selectOption(`#mv-${fp}`, 'faux_positif')
  const kd = k.locator('dialog[open]'); await kd.waitFor()
  check(await kd.locator('[name=reason]').count() === 1 && (await kd.locator('.dialog-body').innerText()).includes('Acme Industrie'), 'Kanban : le faux positif demande un motif et nomme le client')
  await kd.locator('[name=reason]').fill('Tâche planifiée de sauvegarde, connue du client.')
  await kd.locator('button[type=submit]').click(); await kd.waitFor({ state: 'detached' })
  await until(async () => (await k.locator(`section[aria-label="Clôturé"]`).innerText()).includes(fp), 'carte rangée avec les clos')
  check(true, 'Kanban : faux positif clos avec son motif')
  await k.context().close()
}
