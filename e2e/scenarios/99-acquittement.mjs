import { eventually } from '../harness.mjs'

// Délai d'acquittement (ADR-0032) : « Je prends » acquitte le ticket ; le pilotage montre le délai par criticité ;
// le rapport remis au client ne le contient que si le manager l'a choisi dans la politique du client.
export default async ({ BASE, check, login, stack }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const made = await send({ timestamp: new Date().toISOString(), id: 'acq1', rule: { id: '100902', level: 15, description: 'acquittement critique', groups: ['exfiltration'] }, agent: { id: '032', name: 'srv-acq', ip: '10.20.1.32' }, full_log: 'x' })
  check(made.status === 'created', `alerte critique ingérée (${made.ticket})`)
  const a = await login('analyste')
  await a.goto(`${BASE}/tickets/${made.ticket}`)
  const faits = a.locator('dl.ticket-facts')
  await faits.waitFor()
  check((await faits.innerText()).includes('Pas encore'), 'fiche : pas encore acquitté')
  await faits.getByRole('button', { name: 'Je prends' }).click()
  check(await eventually(async () => /Acquitté\s*en .+, par analyste/.test(await faits.innerText())), 'Je prends : ticket acquitté, délai et auteur affichés')
  check(await faits.getByRole('button', { name: 'Je prends' }).count() === 0, 'Je prends : bouton retiré une fois le ticket à soi')

  const m = await login('manager')
  await m.goto(`${BASE}/pilotage`)
  const bloc = m.locator('section[aria-label="Délai d\'acquittement"]')
  const vu = await eventually(async () => (await bloc.count()) === 1 && /critique/i.test(await bloc.innerText()), 10000)
  check(vu, "pilotage : délai d'acquittement par criticité")

  const rapport = async () => (await m.request.get(`${BASE}/api/v1/reports/period?client=ACME`)).json()
  check(!('acquittement' in await rapport()), 'rapport client : délai absent par défaut')
  await m.goto(`${BASE}/politique`)
  const acme = m.locator('section[aria-label="Acme Industrie"]')
  await acme.getByLabel(/Inclure le délai d'acquittement/).check()
  await acme.getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => 'acquittement' in await rapport()), 'rapport client : délai présent une fois activé par le manager')
}
