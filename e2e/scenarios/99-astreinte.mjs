import { eventually } from '../harness.mjs'

// Astreinte (ADR-0032, partie 2) : l'Admin déclare un canal (adresse jamais réaffichée), le manager le choisit pour
// un client et règle criticités et délais. L'envoi lui-même est vérifié par les tests du serveur (faux webhook) ;
// l'adresse choisie ici est refusée par la règle de sortie, aucun appel ne sort de la machine.
export default async ({ BASE, check, login }) => {
  const adm = await login('admin')
  await adm.goto(`${BASE}/admin/astreinte`)
  const ajout = adm.locator('section[aria-label="Ajouter un canal"]')
  await ajout.waitFor()
  await ajout.getByLabel('Nom').fill('astreinte-e2e')
  await ajout.getByLabel('Type').selectOption('webhook_mattermost')
  await ajout.getByLabel(/Adresse du webhook/).fill('https://127.0.0.1:9/hooks/JETON-E2E-SECRET')
  await ajout.getByRole('button', { name: 'Ajouter le canal' }).click()
  const liste = adm.locator('section[aria-label="Canaux d\'astreinte"]')
  check(await eventually(async () => /astreinte-e2e/i.test(await liste.innerText())), 'Admin : canal ajouté')
  check(!/JETON-E2E-SECRET/i.test(await liste.innerText()), 'Admin : adresse du webhook jamais réaffichée')
  await liste.getByRole('button', { name: 'Envoyer un essai' }).click()
  check(await eventually(async () => /Échec de l’essai \(adresse_refusee/.test(await liste.innerText())), 'Admin : essai refusé par la règle de sortie')

  const m = await login('manager')
  await m.goto(`${BASE}/politique`)
  const acme = m.locator('section[aria-label="Acme Industrie"]')
  await acme.waitFor()
  await acme.getByLabel("Canal d'astreinte").selectOption({ label: 'astreinte-e2e' })
  await acme.getByLabel("Prévenir l'astreinte à l'ouverture d'un ticket de ce client").check()
  await acme.getByLabel('Élevée : prévenir l’astreinte').check()
  await acme.getByLabel('Critique : escalade après (minutes)').fill('5')
  await acme.getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /Enregistré/.test(await acme.innerText())), 'manager : astreinte réglée pour ACME')
  const p = await (await m.request.get(`${BASE}/api/v1/politique`)).json()
  const a = p.items.find((x) => x.key === 'ACME').astreinte
  check(a.active && a.criticites.join() === 'Critique,Élevée' && a.delais.Critique === 5, `politique enregistrée (${JSON.stringify(a)})`)
  // remise à l'état d'origine pour les scénarios suivants
  await acme.getByLabel("Prévenir l'astreinte à l'ouverture d'un ticket de ce client").uncheck()
  await acme.getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => !(await (await m.request.get(`${BASE}/api/v1/politique`)).json()).items.find((x) => x.key === 'ACME').astreinte.active), 'astreinte désactivée à nouveau')
}
