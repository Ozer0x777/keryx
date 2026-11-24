// Parc d'agents (ADR-0030) : ticket « agent déconnecté » ouvert à la main depuis le parc (en fin de suite : il crée un
// ticket, ce qui décalerait les références attendues par les scénarios précédents). Le parc vient de 04-parc.mjs.
export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  await m.goto(`${BASE}/parc?client=ACME&agent=002`)
  await m.waitForSelector('.parc-detail h2:has-text("srv-web-02")')
  await m.getByRole('button', { name: 'Ouvrir un ticket « agent déconnecté »' }).click()
  const d = m.locator('dialog[open]'); await d.waitFor()
  check((await d.locator('h2').innerText()).includes('srv-web-02'), 'confirmation nommant l\'agent')
  await d.locator('button[type=submit]').click(); await d.waitFor({ state: 'detached' })
  await m.waitForSelector('.parc-detail a.btn-link')
  const ref = await m.locator('.parc-detail a.btn-link').first().innerText()
  check(/^ACME-\d+$/.test(ref), `ticket ouvert depuis le parc (${ref})`)
  await m.locator('.parc-detail a.btn-link').first().click()
  await m.waitForSelector('.ticket-head')
  check((await m.locator('.ticket-head h1').innerText()).includes('Agent Wazuh déconnecté'), 'le ticket décrit l\'agent déconnecté')
  check(m.errors.length === 0, 'aucune erreur JavaScript')
  await m.context().close()
}
