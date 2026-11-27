import { eventually, unfold } from '../harness.mjs'

// Lier des tickets : recherche par champ (IP relevée dans l'alerte), endroit trouvé, sens parent, suggestions.
export default async ({ BASE, check, login, stack }) => {
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) }).then((r) => r.json())
  const ip = '198.51.100.77'
  const a = (await send({ timestamp: new Date().toISOString(), id: 'lk1', rule: { id: '100950', level: 10, description: 'liens : source A', groups: ['t'] }, agent: { id: '060', name: 'srv-lien-a', ip: '10.20.6.1' }, data: { srcip: ip }, full_log: 'x' })).ticket
  const b = (await send({ timestamp: new Date().toISOString(), id: 'lk2', rule: { id: '100951', level: 10, description: 'liens : source B', groups: ['t'] }, agent: { id: '061', name: 'srv-lien-b', ip: '10.20.6.2' }, data: { src_ip: ip }, full_log: 'y' })).ticket
  const m = await login('analyste')
  await m.goto(`${BASE}/tickets/${a}`)
  await unfold(m, 'Tickets liés')
  const sec = m.locator('section[aria-label="Tickets liés"]')
  const vuSugg = await eventually(async () => (await sec.locator('.suggest').count()) === 1 && (await sec.locator('.suggest').innerText()).includes(ip), 10000)
  const api = vuSugg ? '' : ` (API : ${await m.request.get(`${BASE}/api/v1/tickets/${a}/links/suggestions`).then(async (r) => `${r.status()} ${(await r.text()).slice(0, 300)}`)} ; a=${a} b=${b} ; fiche : ${(await sec.innerText()).replace(/\s+/g, ' ').slice(0, 160)})`
  check(vuSugg && (await sec.locator('.suggest').innerText()).includes(b), `suggestion : un autre ticket avec la même adresse${api}`)
  await sec.getByRole('button', { name: 'Voir et lier' }).first().click()
  const d = m.locator('dialog.link-dialog')
  check(await d.locator('input[type=search]').inputValue() === `ip:${ip}`, 'fenêtre ouverte sur la valeur suggérée')
  const ligne = d.locator('.link-results li').filter({ has: m.locator('.mono', { hasText: new RegExp(`^${b}$`) }) })
  await ligne.waitFor()
  check((await ligne.innerText()).includes('data.src_ip'), 'résultat : trouvé dans l\'alerte brute, champ data.src_ip')
  await d.locator('label.link-kind', { hasText: 'Parent / enfant' }).click()
  await d.getByLabel(`${a} est le parent de…`).check()
  await ligne.locator('input[type=radio]').check()
  check((await d.locator('.link-effect').innerText()).includes(`${a} devient le parent de ${b}`), 'conséquence écrite avant de valider')
  await d.getByRole('button', { name: `Lier comme parent de ${b}` }).click()
  await m.waitForSelector(`.linklist >> text=${b}`)
  check((await sec.locator('.linkgroup', { hasText: b }).locator('h3').innerText()).toLowerCase().includes('enfants'), 'lien affiché dans le groupe « Enfants »')
  await m.goto(`${BASE}/tickets/${b}`)
  await unfold(m, 'Tickets liés')
  const groupe = m.locator('section[aria-label="Tickets liés"] .linkgroup', { hasText: a })
  const ok = await eventually(async () => (await groupe.count()) === 1 && (await groupe.locator('h3').innerText()).toLowerCase().includes('parent'))
  const vu = ok ? '' : ` (affiché : ${(await m.locator('section[aria-label="Tickets liés"]').innerText()).replace(/\s+/g, ' ').slice(0, 200)})`
  check(ok, `vu de l'autre ticket : groupe « Parent »${vu}`)
  await m.goto(`${BASE}/tickets?q=${encodeURIComponent('ip:' + ip)}`)
  check(await eventually(async () => { const txt = await m.locator('tbody').innerText(); return txt.includes(a) && txt.includes(b) }), 'file : recherche ip: trouve les deux tickets')
  check(m.errors.length === 0, 'aucune erreur JavaScript')
}
