import { eventually, sql } from '../harness.mjs'

// Battement de cœur (ADR-0032, partie 3) : le manager l'active pour un client ; un battement reçu ne crée aucun ticket
// et s'affiche ; une absence (simulée en base, la tâche de fond n'attend pas 15 minutes ici) affiche un bandeau à
// l'équipe ; le battement suivant l'efface.
export default async ({ BASE, check, login, stack }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) })
  const battement = { timestamp: new Date().toISOString(), id: 'bat1', rule: { id: '119990', level: 3, description: 'Keryx : battement de cœur de la chaîne d\'alerte', groups: ['keryx_battement'] }, agent: { id: '000', name: 'wazuh-e2e' }, manager: { name: 'wazuh-e2e' } }

  const m = await login('manager')
  await m.goto(`${BASE}/politique`)
  const acme = m.locator('section[aria-label="Acme Industrie"]')
  await acme.waitFor()
  await acme.getByLabel('Surveiller le battement de cœur de ce client').check()
  await acme.getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /Enregistré/.test(await acme.innerText())), 'manager : battement activé pour ACME')

  const avant = (await (await m.request.get(`${BASE}/api/v1/tickets?client=ACME&limit=1`)).json()).total
  const r = await send(battement)
  check(r.status === 202 && (await r.json()).status === 'battement', 'battement reçu (202)')
  const apres = (await (await m.request.get(`${BASE}/api/v1/tickets?client=ACME&limit=1`)).json()).total
  check(avant === apres, `aucun ticket créé par le battement (${avant} → ${apres})`)
  await m.reload()
  check(await eventually(async () => /Dernier battement : .*wazuh-e2e/.test(await m.locator('section[aria-label="Acme Industrie"]').innerText())), 'manager : dernier battement affiché')

  sql(stack, "UPDATE tenants SET battement_manquant_at = ?, battement_at = ? WHERE key = 'ACME'", '2026-01-01 00:15:00', '2026-01-01 00:00:00')
  const a = await login('analyste')
  await a.goto(`${BASE}/tickets`)
  check(await eventually(async () => (await a.getByTestId('chaine-muette').count()) === 1), 'analyste : bandeau « chaîne d\'alerte muette »')
  check(/Acme Industrie/.test(await a.getByTestId('chaine-muette').innerText()), 'bandeau : nomme le client')
  await send({ ...battement, id: 'bat2' })
  await a.reload()
  await a.locator('h1').first().waitFor()
  check(await eventually(async () => (await a.getByTestId('chaine-muette').count()) === 0), 'battement revenu : bandeau effacé')

  await m.goto(`${BASE}/politique`)
  await acme.getByLabel('Surveiller le battement de cœur de ce client').uncheck()
  await acme.getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /Enregistré/.test(await acme.innerText())), 'battement désactivé à nouveau')
}
