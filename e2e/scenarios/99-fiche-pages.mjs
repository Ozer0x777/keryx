import { eventually, unfold } from '../harness.mjs'

// Fiche d'un ticket très actif : la fiche ne reçoit que les 100 entrées d'historique les plus récentes, les plus
// anciennes se chargent à la demande. Placé en fin de parcours : les occurrences ajoutées ne faussent aucun compteur.
export default async ({ stack, BASE, check, login }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const meme = { timestamp: '2026-11-25T09:00:00.000+0000', rule: { id: '120999', level: 10, description: 'règle bavarde', groups: ['test'] },
    agent: { id: '399', name: 'srv-bavard', ip: '10.20.3.9' }, full_log: 'x' }
  let ref
  for (let i = 0; i < 115; i++) ref = (await send({ ...meme, id: `occ${i}` })).ticket
  const m = await login('manager')
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector('.ticket-head')
  await unfold(m, 'Registre des actions')
  const lignes = m.locator('section[aria-label="Registre des actions"] ol.timeline > li')
  check(await eventually(async () => (await lignes.count()) === 100), 'fiche : les 100 entrées les plus récentes du registre')
  const plus = m.getByRole('button', { name: /Afficher les plus anciens \(\d+ restants\)/ })
  check(await plus.isVisible(), 'fiche : bouton « Afficher les plus anciens » avec le nombre restant')
  await plus.click()
  check(await eventually(async () => (await lignes.count()) > 100 && !(await plus.isVisible())), 'fiche : les plus anciennes chargées, plus de bouton')
  const rapport = await m.request.get(`${BASE}/api/v1/tickets/${ref}?complet=true`)
  const r = await rapport.json()
  // Les occurrences d'alerte ne sont pas listées une à une dans les rapports : elles sont résumées (nombre, dates).
  check(!r.events.some((e) => e.action === 'occurrence') && r.events.length + r.occurrences_resume.nombre === await lignes.count() && r.events_older === 0,
    'rapport : registre complet, occurrences résumées (total égal à la fiche dépliée)')
}
