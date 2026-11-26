import { eventually, unfold } from '../harness.mjs'

// Suivi par le client (PDIS IV.2.3.l) : le client modifie l'état de son côté et demande la clôture ; l'équipe le
// voit, demande une action ; le client la met à jour.
export default async ({ BASE, check, login, stack }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const made = await send({ timestamp: new Date().toISOString(), id: 'suivi1', rule: { id: '100903', level: 10, description: 'suivi par le client', groups: ['test'] }, agent: { id: '033', name: 'poste-suivi', ip: '10.20.1.33' }, full_log: 'x' })
  const ref = made.ticket
  const c = await login('client')
  await c.goto(`${BASE}/tickets/${ref}`)
  await unfold(c, 'Votre suivi')
  await c.getByLabel('État de votre côté').selectOption('en_cours')
  await c.getByRole('button', { name: "Enregistrer l'état" }).click()
  check(await eventually(async () => /En cours de traitement chez nous/.test(await c.locator('main').innerText())), 'client : état enregistré')
  await c.getByRole('button', { name: 'Demander la clôture' }).click()
  check(await eventually(async () => /demande la clôture/.test(await c.locator('main').innerText())), 'client : demande de clôture envoyée')

  const a = await login('analyste')
  await a.goto(`${BASE}/tickets/${ref}?onglet=communication`)
  await unfold(a, 'Suivi par le client')
  check(await eventually(async () => /Le client demande la clôture du ticket/.test(await a.locator('main').innerText())), 'équipe : demande du client visible')
  await a.getByLabel('Nouvelle action demandée au client').fill('Isoler le poste du réseau')
  await a.getByRole('button', { name: 'Demander cette action' }).click()
  check(await eventually(async () => /Isoler le poste du réseau/.test(await a.locator('main').innerText())), 'équipe : action demandée au client')

  await c.reload()
  await unfold(c, 'Votre suivi')
  const etat = c.locator('ul.stack > li', { hasText: 'Isoler le poste du réseau' }).getByLabel('État')
  await etat.selectOption('faite')
  await c.locator('ul.stack > li', { hasText: 'Isoler le poste du réseau' }).getByRole('button', { name: 'Mettre à jour' }).click()
  check(await eventually(async () => /Faite/.test(await c.locator('ul.stack > li', { hasText: 'Isoler le poste du réseau' }).innerText())), 'client : action marquée faite')
}
