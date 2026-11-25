// Parc d'agents Wazuh (ADR-0030) : parc inséré en base (aucun manager Wazuh dans le banc), vue de l'équipe et du client.
// Placé en tête : les contrôles de mise en page, de traduction et d'accessibilité qui suivent voient une page remplie.
import { eventually, sql, until } from '../harness.mjs'

const ts = (msAgo) => new Date(Date.now() - msAgo).toISOString().replace('T', ' ').replace('Z', '').padEnd(26, '0')
const H = 3600e3

export default async ({ stack, BASE, check, login }) => {
  const tenant = "(select id from tenants where key = 'ACME')"
  sql(stack, `update tenants set wazuh_manager_version = '4.12.0', wazuh_agents_polled_at = ? where key = 'ACME'`, ts(120e3))
  const agents = [
    ['001', 'srv-ad-01', 'active', '4.12.0', 0, 0.01],
    ['002', 'srv-web-02', 'disconnected', '4.9.2', 50 * H, 50],
    ['003', 'srv-web-01', 'active', '4.11.2', 0, 0.01],
    ['004', 'pc-rh-03', 'disconnected', '4.12.0', 2 * H, 2],
    ['005', 'pc-dev-12', 'never_connected', null, 6 * 24 * H, null],
  ]
  for (const [id, name, status, version, since, keep] of agents) {
    sql(stack, `insert into wazuh_agents (id, tenant_id, agent_id, name, ip, os_name, os_version, version, status, groups, node,
      last_keepalive, registered_at, last_event_at, status_since, updated_at) values (?, ${tenant}, ?, ?, ?, 'Ubuntu', '24.04', ?, ?, '["default","acme"]', 'worker-01', ?, ?, null, ?, ?)`,
      `e2e-agent-${id}`, id, name, `10.20.0.${Number(id)}`, version, status, keep == null ? null : ts(keep * H), ts(30 * 24 * H), ts(since), ts(0))
    sql(stack, `insert into wazuh_agent_events (id, tenant_id, agent_id, status, previous, source, at) values (?, ${tenant}, ?, 'active', null, '', ?)`,
      `e2e-ev-a-${id}`, id, ts(8 * 24 * H))
    if (status !== 'active') sql(stack, `insert into wazuh_agent_events (id, tenant_id, agent_id, status, previous, source, at) values (?, ${tenant}, ?, ?, 'active', '', ?)`,
      `e2e-ev-b-${id}`, id, status, ts(since))
  }

  const m = await login('manager')
  await m.goto(`${BASE}/parc?client=ACME`)
  await m.waitForSelector('.parc-layout')
  check((await m.locator('nav').innerText()).includes('Parc Wazuh'), 'menu : entrée « Parc Wazuh » pour l\'équipe')
  const banner = await m.locator('.banner.danger').innerText()
  check(banner.includes('1 agent(s) hors ligne depuis plus de 24 h'), 'alerte : un agent hors ligne depuis plus de 24 h')
  const card = (label) => m.locator('.stat-filter', { hasText: label })
  check((await card('Versions en retard').locator('strong').innerText()) === '2', 'carte : deux versions en retard')
  check(await m.locator('.stat-filter', { hasText: 'Silencieux' }).count() === 0, 'carte « Silencieux » masquée sans indexeur relié')
  const first = await m.locator('tbody tr').first().innerText()
  check(first.includes('srv-web-02') && first.includes('très ancienne'), 'tableau : le plus urgent en tête, version très ancienne signalée')
  await card('Hors ligne > 24 h').click()
  await until(async () => (await m.locator('tbody tr').count()) === 1, 'filtre hors ligne > 24 h')
  check(m.url().includes('filtre=down24'), 'filtre inscrit dans l\'URL')
  await m.getByRole('button', { name: 'Voir le détail de srv-web-02' }).click()
  await m.waitForSelector('.parc-detail h2:has-text("srv-web-02")')
  let detail = '', segs = []
  const lire = async () => {
    detail = await m.locator('.parc-detail').innerText()
    segs = await m.locator('.parc-timeline .seg').evaluateAll((l) => l.map((e) => e.className + ':' + e.style.flexBasis))
    return /disponibilité sur 7 jours/i.test(detail) && segs.some((x) => x.includes('disconnected')) && detail.includes('Ouvrir un ticket « agent déconnecté »')
  }
  await eventually(lire)
  check(/disponibilité sur 7 jours/i.test(detail) && segs.some((x) => x.includes('disconnected')), `détail : disponibilité et barre des 7 jours (${segs.join(' ')})`)
  check(detail.includes('Ouvrir un ticket « agent déconnecté »'), 'détail : bouton de ticket pour un agent déconnecté')
  await m.context().close()

  const c = await login('client')
  await c.goto(`${BASE}/parc`)
  await c.waitForSelector('.parc-layout')
  check((await c.locator('nav').innerText()).includes('Mon parc'), 'portail client : entrée « Mon parc »')
  check(await c.locator('tbody tr').count() === 5, 'portail client : ses cinq agents')
  check(await c.getByRole('button', { name: 'Relever maintenant' }).count() === 0 && await c.getByRole('button', { name: 'Exporter (CSV)' }).count() === 0, 'portail client : ni relevé ni export')
  await c.getByRole('button', { name: 'Voir le détail de srv-web-02' }).click()
  await c.waitForSelector('.parc-detail h2:has-text("srv-web-02")')
  check(await c.getByRole('button', { name: /Ouvrir un ticket/ }).count() === 0 && !(await c.locator('.parc-detail').innerText()).includes('worker-01'), 'portail client : ni ticket ni nœud du manager')
  await c.context().close()
}
