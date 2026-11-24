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
  m.on('dialog', (x) => x.accept())    // beforeunload au rechargement
  await m.reload()
  await m.waitForSelector('.ticket-head')
  await unfold(m, 'Commentaires')
  await m.waitForSelector('text=Brouillon retrouvé')
  check((await m.locator('section[aria-label="Commentaires"] .rich-content').last().innerText()).includes('Brouillon à ne pas perdre.'), 'brouillon : le commentaire est retrouvé après rechargement')

  // Commentaire visible par le client : confirmation qui nomme le client, annulable
  await m.getByLabel('Visible par le client').check()
  await m.getByRole('button', { name: 'Publier', exact: true }).click()
  const c = m.locator('dialog[open]'); await c.waitFor()
  check((await c.locator('h2').innerText()).includes('client') && (await c.locator('button[type=submit]').innerText()).includes('Publier au client'), 'commentaire visible : confirmation nommant le client')
  await c.locator('button[data-cancel]').click(); await c.waitFor({ state: 'detached' })
  check(await m.locator('.comment').count() === 0, 'commentaire visible : annuler ne publie rien')
  await m.getByLabel('Visible par le client').uncheck()
  await m.getByRole('button', { name: 'Publier', exact: true }).click()   // interne : aucune confirmation
  await m.waitForSelector('.comment.internal')
  check(await m.locator('.head-status .unsaved-summary').count() === 0, 'publication : plus de saisie en attente, brouillon vidé')
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
}
