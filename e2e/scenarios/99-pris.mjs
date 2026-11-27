import { eventually, unfold } from '../harness.mjs'

// Réponse aux incidents (PRIS v3.2) : posture en discrétion élevée, compréhension structurée, mesure d'endiguement
// proposée par l'équipe et acceptée par le client, rapport d'analyse et point de situation.
export default async ({ BASE, check, login, stack }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const ref = (await send({ timestamp: new Date().toISOString(), id: 'pris1', rule: { id: '100904', level: 12, description: 'réponse aux incidents', groups: ['test'] }, agent: { id: '034', name: 'srv-pris', ip: '10.20.1.34' }, full_log: 'x' })).ticket
  const a = await login('analyste')
  await a.goto(`${BASE}/tickets/${ref}?onglet=investigation`)
  await unfold(a, 'Posture')
  await a.getByLabel("Niveau de discrétion vis-à-vis de l'attaquant").selectOption('eleve')
  await a.locator('section[aria-label="Posture"]').getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /Enregistré/.test(await a.locator('section[aria-label="Posture"]').innerText())), 'posture : discrétion élevée enregistrée')
  await unfold(a, "Compréhension de l'incident")
  await a.getByLabel("L'attaquant est-il toujours présent ?").selectOption('oui')
  await a.getByLabel('Mode opératoire : compromission initiale').fill('Hameçonnage ciblé')
  await a.locator('section[aria-label="Compréhension de l\'incident"]').getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /Enregistré/.test(await a.locator('section[aria-label="Compréhension de l\'incident"]').innerText())), 'compréhension structurée enregistrée')
  await unfold(a, "Mesures d'endiguement et procédures d'urgence")
  await a.getByLabel('Nouvelle mesure').fill('Isoler le serveur du réseau')
  await a.getByRole('button', { name: 'Proposer' }).click()
  check(await eventually(async () => /Isoler le serveur du réseau/.test(await a.locator('section[aria-label="Mesures d\'endiguement et procédures d\'urgence"]').innerText())), 'mesure proposée')

  const c = await login('client')
  await c.goto(`${BASE}/tickets/${ref}`)
  await c.locator('section[aria-label="Mesures d\'endiguement et procédures d\'urgence"]').waitFor()
  await c.locator('section[aria-label="Mesures d\'endiguement et procédures d\'urgence"]').getByRole('button', { name: 'Accepter' }).click()
  check(await eventually(async () => /Acceptée par le commanditaire/.test(await c.locator('section[aria-label="Mesures d\'endiguement et procédures d\'urgence"]').innerText())), 'client : mesure acceptée')

  await a.goto(`${BASE}/tickets/${ref}/rapport-analyse`)
  const rap = a.locator('article[aria-label="Rapport d\'analyse"]')
  await rap.waitFor()
  const txt = await rap.innerText()
  check(/1\. Qualification de la prestation/.test(txt) && /5\. Annexes/.test(txt) && /Hameçonnage ciblé/.test(txt) && /Isoler le serveur/.test(txt), "rapport d'analyse : sections et données reprises")
  await a.goto(`${BASE}/tickets/${ref}/point-situation`)
  check(await eventually(async () => /mesure_acceptee|Élevée/.test(await a.locator('main').innerText())), 'point de situation : activité et posture')
}
