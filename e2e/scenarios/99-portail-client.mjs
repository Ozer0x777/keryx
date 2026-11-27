import { eventually, unfold } from '../harness.mjs'

// Portail client : titre et résumé écrits par l'équipe, statut en mots de client, « Votre réponse attendue »,
// décision depuis « À faire de votre côté », technique repliée en fin de page.
export default async ({ BASE, check, login, stack }) => {
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) }).then((r) => r.json())
  const ref = (await send({ timestamp: new Date().toISOString(), id: 'pc1', rule: { id: '100970', level: 12, description: 'Powershell process spawned', groups: ['t'] }, agent: { id: '080', name: 'srv-portail', ip: '10.20.8.1' }, full_log: 'x' })).ticket
  const a = await login('analyste')
  await a.goto(`${BASE}/tickets/${ref}?onglet=communication`)
  await unfold(a, 'Ce que lit le client')
  await a.getByLabel('Titre pour le client').fill('Programme inconnu lancé sur un serveur')
  await a.getByLabel('Ce qui se passe (résumé pour le client)').fill('Un programme inconnu a tenté de joindre une adresse extérieure.')
  await a.locator('section[aria-label="Ce que lit le client"]').getByRole('button', { name: 'Enregistrer' }).click()
  check(await eventually(async () => /résumé à jour du/.test(await a.locator('section[aria-label="Ce que lit le client"] .fold-summary').innerText())), 'équipe : titre et résumé pour le client enregistrés')
  await a.goto(`${BASE}/tickets/${ref}?onglet=investigation`)
  await unfold(a, "Mesures d'endiguement et procédures d'urgence")
  await a.getByLabel('Nouvelle mesure').fill('Isoler le serveur du réseau')
  await a.getByRole('button', { name: 'Proposer' }).click()
  await a.waitForSelector('section[aria-label="Mesures d\'endiguement et procédures d\'urgence"] >> text=Isoler le serveur du réseau')

  const c = await login('client')
  check(await eventually(async () => c.url().endsWith('/accueil')), 'client : arrivée sur son accueil')
  const todoAccueil = c.locator('section[aria-label="À faire de votre côté"]')
  check(await eventually(async () => (await todoAccueil.count()) === 1 && (await todoAccueil.innerText()).includes('Isoler le serveur du réseau')), 'accueil : la mesure attend sa décision')
  await c.locator('.bell-btn').click()
  check(await eventually(async () => (await c.locator('.bell-panel').innerText()).includes('Décision attendue de votre part')), 'cloche du client : « Décision attendue de votre part »')
  await c.goto(`${BASE}/tickets`)
  const ligne = c.locator('table.queue-client tbody tr', { hasText: ref })
  await ligne.waitFor()
  check((await ligne.innerText()).includes('Programme inconnu lancé sur un serveur') && (await ligne.innerText()).includes('Votre réponse attendue'), 'liste du client : titre pour le client et « Votre réponse attendue »')
  await c.getByRole('button', { name: 'Votre réponse attendue' }).click()
  check(await eventually(async () => (await c.locator('table.queue-client tbody tr', { hasText: ref }).count()) === 1 && c.url().includes('a_decider=1')), 'filtre « Votre réponse attendue »')
  await c.goto(`${BASE}/tickets/${ref}`)
  const todo = c.locator('section[aria-label="À faire de votre côté"]')
  await todo.waitFor()
  check((await c.locator('section[aria-label="Ce qui se passe"]').innerText()).includes('adresse extérieure'), 'fiche du client : « Ce qui se passe »')
  check(await c.locator('details.tech-details').evaluate((d) => !d.open), 'fiche du client : détails techniques repliés')
  await todo.getByRole('button', { name: 'Autoriser' }).click()
  check(await eventually(async () => (await c.locator('section[aria-label="À faire de votre côté"]').count()) === 0), 'décision enregistrée : plus rien à faire de son côté')
  check(c.errors.length === 0 && a.errors.length === 0, 'aucune erreur JavaScript')
}
