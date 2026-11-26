import { eventually, unfold } from '../harness.mjs'

// Politique du client (ADR-0033) : le manager fixe un TLP plancher ; l'analyste ne peut plus descendre en dessous,
// le manager le peut avec un motif. En fin de parcours : le plancher relève des tickets ouverts.
export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  await m.goto(`${BASE}/politique`)
  const acme = m.locator('section[aria-label="Acme Industrie"]')
  await acme.waitFor()
  check((await m.locator('nav').innerText()).includes('Politique des clients'), 'menu du manager : « Politique des clients »')
  await acme.getByLabel('TLP plancher').selectOption('TLP:AMBER+STRICT')
  await acme.getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /Enregistré/.test(await acme.innerText())), 'plancher enregistré, tickets ouverts relevés annoncés')

  // un ticket ouvert d'ACME (ACME-1 a pu être clos par les scénarios précédents)
  const liste = await (await m.request.get(`${BASE}/api/v1/tickets?status=nouveau&client=ACME&limit=1`)).json()
  const ref = liste.items[0].ref
  const a = await login('analyste')
  await a.goto(`${BASE}/tickets/${ref}`)
  await unfold(a, 'Qualification')
  const marquage = a.getByLabel('Marquage')
  check(await eventually(async () => ['TLP:AMBER+STRICT', 'TLP:RED'].includes(await marquage.inputValue())), `ticket ouvert ${ref} relevé au plancher`)
  const desactives = await marquage.evaluate((sel) => [...sel.options].filter((o) => o.disabled).map((o) => o.value))
  check(['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER'].every((x) => desactives.includes(x)) && !desactives.includes('TLP:RED'),
    `analyste : niveaux sous le plancher désactivés (${desactives.join(', ')})`)
  check((await a.locator('section[aria-label="Qualification"]').innerText()).includes('TLP plancher de ce client : TLP:AMBER+STRICT'), 'analyste : plancher expliqué')

  await m.goto(`${BASE}/tickets/${ref}`)
  await unfold(m, 'Qualification')
  await m.getByLabel('Marquage').selectOption('TLP:GREEN')
  check(await m.getByLabel(/Motif du passage sous le TLP plancher/).isVisible(), 'manager : sous le plancher, un motif est demandé')
}
