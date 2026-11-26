import { eventually, until } from '../harness.mjs'

// File des tickets : pagination (page et taille de page dans l'URL, retour à la page 1 quand un filtre change,
// bouton Précédent du navigateur). Placé en fin de parcours : les 30 tickets ajoutés ne faussent aucun compteur.
export default async ({ stack, BASE, check, login }) => {
  const send = (alert) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  for (let i = 0; i < 30; i++) {
    await send({ timestamp: '2026-11-25T08:00:00.000+0000', id: `pg${i}`, rule: { id: `1209${String(i).padStart(2, '0')}`, level: 10, description: `pagination ${i}`, groups: ['test'] },
      agent: { id: `3${String(i).padStart(2, '0')}`, name: `srv-page-${i}`, ip: '10.20.3.1' }, full_log: 'x' })
  }
  const m = await login('manager')
  await m.goto(`${BASE}/tickets?per_page=25`)
  await m.waitForSelector('tbody tr')
  const compte = async () => m.locator('.list-count').innerText()
  await until(async () => /^Tickets 1 à 25 sur \d+$/.test(await compte()), 'compte de la première page')
  const total = Number((await compte()).match(/sur (\d+)/)[1])
  check(total > 30 && (await m.locator('tbody tr').count()) === 25, `page 1 : 25 tickets affichés sur ${total}`)
  const nav = m.getByRole('navigation', { name: 'Pages de la liste' })
  check(await nav.getByRole('button', { name: 'Précédente' }).isDisabled(), 'page 1 : « Précédente » désactivé')
  const pages = Math.ceil(total / 25)
  check((await nav.innerText()).includes(`Page 1 sur ${pages}`), `page 1 sur ${pages} annoncée`)
  await nav.getByRole('button', { name: 'Suivante' }).click()
  await m.waitForFunction(() => location.search.includes('page=2'))
  check(await eventually(async () => (await compte()).startsWith('Tickets 26 à ')), 'page 2 : compte à partir du 26e')
  check(m.url().includes('per_page=25'), 'la taille de page reste dans l\'URL')
  await m.goBack()
  check(await eventually(async () => (await compte()).startsWith('Tickets 1 à 25')), 'bouton Précédent du navigateur : retour à la page 1')
  await nav.getByRole('button', { name: 'Dernière' }).click()
  check(await eventually(async () => (await nav.innerText()).includes(`Page ${pages} sur ${pages}`) && await nav.getByRole('button', { name: 'Suivante' }).isDisabled()), 'dernière page : « Suivante » désactivé')
  // un filtre qui change ramène à la page 1
  await m.getByRole('searchbox').first().fill('pagination')
  await m.keyboard.press('Enter')
  check(await eventually(async () => [null, '1'].includes(new URL(m.url()).searchParams.get('page'))), 'un filtre qui change ramène à la page 1')
  check(await eventually(async () => (await compte()).startsWith('Tickets 1 à 25 sur 30')), 'recherche « pagination » : 30 tickets, page 1')
  await nav.getByLabel('Tickets par page').selectOption('50')
  check(await eventually(async () => (await compte()) === '30 ticket(s)' && (await m.locator('tbody tr').count()) === 30), '50 par page : les 30 tickets sur une seule page')
}
