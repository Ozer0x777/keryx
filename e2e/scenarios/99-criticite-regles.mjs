import { eventually } from '../harness.mjs'

// Criticité par règle Wazuh : le manager l'impose pour tous ses clients, puis la retire pour l'un d'eux.
export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  await m.goto(`${BASE}/politique`)
  const s = m.locator('section[aria-label="Criticité par règle Wazuh"]')
  await s.waitFor()
  await s.getByLabel('Identifiant de la règle').fill('60148')
  await s.getByLabel('Criticité initiale').selectOption('Élevée')
  await s.getByRole('button', { name: 'Appliquer' }).click()
  check(await eventually(async () => /ACME : Élevée · DELTA : Élevée/.test(await s.innerText())), 'règle imposée pour tous les clients')
  await s.getByLabel('Transports Delta').check()
  await s.getByRole('button', { name: 'Retirer cette règle' }).click()
  check(await eventually(async () => /ACME : Élevée/.test(await s.innerText()) && !/DELTA : Élevée/.test(await s.innerText())), 'règle retirée pour un seul client')
  await s.getByLabel('Tous mes clients').check()
  await s.getByRole('button', { name: 'Retirer cette règle' }).click()
  check(await eventually(async () => /Aucune criticité imposée/.test(await s.innerText())), 'règle retirée partout')
}
