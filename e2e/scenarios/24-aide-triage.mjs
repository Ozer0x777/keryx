// Aide au triage (ADR-0028) : titre court, écart d'horloge signalé, gravité proposée retenue d'un clic.
import { unfold, until } from '../harness.mjs'

export default async ({ stack, BASE, check, login }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const commande = 'Powershell process spawned with suspicious command line: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
  const enAvance = new Date(Date.now() + 4 * 60000).toISOString().replace('Z', '+0000')   // horloge du manager en avance
  const made = await send({ timestamp: enAvance, id: 'tr1', rule: { id: '92201', level: 12, description: commande, groups: ['windows'] }, agent: { id: '051', name: 'GOAD-SRV02', ip: '10.20.1.51' }, full_log: 'x' })
  const ref = made.ticket
  check(!!ref, `alerte ingérée (${ref})`)

  const m = await login('manager')
  await m.goto(`${BASE}/tickets`)
  await m.waitForSelector(`a:has-text("${ref}")`)
  const ligne = await m.locator('tbody tr', { has: m.locator(`a:has-text("${ref}")`) }).innerText()
  check(ligne.includes('…') && !ligne.includes('EncodedCommand'), 'titre court dans la file, sans la ligne de commande')

  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector('.ticket-head')
  const head = await m.locator('.ticket-head').innerText()
  check(/Horloge du manager Wazuh en avance d'environ [3-5] min/.test(head), 'écart d\'horloge signalé dans l\'en-tête')
  check((await m.locator('section[aria-label="Description"]').innerText()).includes('EncodedCommand'), 'la description complète reste dans le ticket')

  await unfold(m, 'Qualification')
  const prop = m.locator('[data-testid=severity-proposal]')
  check((await prop.innerText()).includes('Gravité proposée') && (await m.locator('section[aria-label="Qualification"] .gravity').innerText()).includes('—'), 'gravité proposée affichée, rien d\'appliqué seul')
  await prop.getByRole('button', { name: 'Retenir cette gravité' }).click()
  await until(async () => (await m.locator('[data-testid=severity-proposal]').count()) === 0, 'proposition retirée')
  check(!(await m.locator('section[aria-label="Qualification"] .gravity').innerText()).includes('—'), 'un clic : gravité retenue, proposition retirée')
  check(await m.locator('.head-status .unsaved-summary.pill').count() === 0, 'aucune saisie laissée en attente après le clic')
  await m.context().close()
}
