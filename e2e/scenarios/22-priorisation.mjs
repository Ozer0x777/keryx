import { eventually, until } from '../harness.mjs'

// File des tickets : vues de priorisation (ADR-0025), chacune est un filtre rapide inscrit dans l'URL.
export default async ({ stack, BASE, check, login }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const crit = { timestamp: '2026-11-22T09:00:00.000+0000', id: 'pr1', rule: { id: '100901', level: 15, description: 'exfiltration critique', groups: ['exfiltration'] }, agent: { id: '031', name: 'srv-prio', ip: '10.20.1.31' }, full_log: 'x' }
  const made = await send(crit)
  check(made.status === 'created', `alerte critique ingérée (${made.ticket})`)

  const m = await login('manager')
  await m.goto(`${BASE}/tickets`)
  await m.waitForSelector('.stats-row .stat-filter')
  const cartes = await m.locator('.stats-row .stat-filter .stat-label').allInnerTexts()
  // Une seule rangée de tuiles : ce qui demande une action d'abord, les trois vues de priorisation comprises.
  check(JSON.stringify(cartes) === JSON.stringify(['Critiques non assignés', 'En retard', 'À qualifier', 'En réponse', 'Critiques ouverts', 'REX en attente', 'En attente du client', 'Dossiers incomplets']), `tuiles sur une rangée, actions d'abord (${cartes.join(' | ')})`)
  const carte = m.locator('.stats-row .stat-filter', { hasText: 'Critiques non assignés' })
  await until(async () => !(await carte.locator('strong').innerText()).includes('…'), 'compteur chargé')
  check(Number(await carte.locator('strong').innerText()) >= 1, 'critiques non assignés : le compteur compte le ticket critique')
  await carte.click()
  await m.waitForFunction(() => location.search.includes('critical_unassigned=1') && !location.search.includes('assignee') && !location.search.includes('severity'))
  check(await eventually(async () => await carte.getAttribute('aria-pressed') === 'true'), 'critiques non assignés : carte enfoncée, critère propre dans l\'URL, vue d\'assigné intacte')
  const ouverts = m.locator('.stats .stat-filter', { hasText: 'Critiques ouverts' })
  check(await eventually(async () => await ouverts.getAttribute('aria-pressed') === 'false'), 'critiques non assignés : « Critiques ouverts » n\'est pas enfoncée en même temps')
  await until(async () => (await m.locator('tbody tr').count()) >= 1 && (await m.locator('tbody').innerText()).includes(made.ticket), 'la liste montre le ticket critique')
  // Une autre vue remplace celle-ci : plus d'assigné ni de gravité cachés
  const attente = m.locator('.stats-row .stat-filter', { hasText: 'En attente du client' })
  await attente.click()
  await m.waitForFunction(() => location.search.includes('awaiting_client=1') && !location.search.includes('assignee') && !location.search.includes('severity'))
  check(await eventually(async () => await attente.getAttribute('aria-pressed') === 'true' && await carte.getAttribute('aria-pressed') === 'false'), 'en attente du client : vue exclusive, filtres précédents retirés')
  await attente.click()
  await m.waitForFunction(() => !location.search.includes('awaiting_client'))
  check(await eventually(async () => await attente.getAttribute('aria-pressed') === 'false'), 'un second clic retire la vue')
  // Second clic sur « Critiques non assignés » : plus aucun filtre derrière
  await carte.click()
  await m.waitForFunction(() => location.search.includes('critical_unassigned=1'))
  await carte.click()
  await m.waitForFunction(() => location.search === '')
  check(await eventually(async () => await carte.getAttribute('aria-pressed') === 'false'), 'second clic sur « Critiques non assignés » : URL vide, aucun filtre caché')
}
