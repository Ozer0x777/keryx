// Captures d'écran de tous les écrans principaux : node shots.mjs <dossier> [largeur]
import { mkdirSync } from 'node:fs'
import { BASE, launch, login, sql, startStack, unfoldAll, waitUp } from './harness.mjs'
const out = process.argv[2]; const width = Number(process.argv[3] || 1400)
mkdirSync(out, { recursive: true })
const stack = startStack()
try {
  await waitUp()
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) })
  const rules = [[7, 'ssh: échec de connexion répété depuis une source externe inconnue'], [10, 'web: tentative d’injection SQL détectée sur le portail client'], [12, 'fim: fichier système modifié'], [14, 'corrélation: exfiltration vers une IP externe']]
  for (let i = 0; i < 4; i++) await send({ id: `s${i}`, timestamp: new Date().toISOString(), rule: { id: String(5700 + i), level: rules[i][0], description: rules[i][1], groups: ['syslog', 'sshd'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } }, agent: { id: `00${i}`, name: `srv-prod-0${i}`, ip: `10.0.0.${i}`, labels: { importance: ['standard', 'sensible', 'vital', 'sensible'][i] } }, full_log: 'Nov 20 sshd[1]: Failed password for root' })
  // Parc d'agents fictif (aucun manager Wazuh dans le banc), comme le scénario 04-parc.
  const ts = (msAgo) => new Date(Date.now() - msAgo).toISOString().replace('T', ' ').replace('Z', '').padEnd(26, '0')
  const H = 3600e3
  const tenant = "(select id from tenants where key = 'ACME')"
  sql(stack, `update tenants set wazuh_manager_version = '4.12.0', wazuh_agents_polled_at = ? where key = 'ACME'`, ts(4 * 60e3))
  const parc = [['001', 'srv-ad-01', 'active', '4.12.0', 0], ['002', 'srv-web-02', 'disconnected', '4.9.2', 50 * H], ['003', 'srv-web-01', 'active', '4.11.2', 0],
    ['004', 'pc-rh-03', 'disconnected', '4.12.0', 2 * H], ['005', 'pc-dev-12', 'never_connected', null, 6 * 24 * H], ['006', 'srv-db-01', 'active', '4.12.0', 0],
    ['007', 'srv-mail-01', 'active', '4.12.0', 0], ['008', 'pc-compta-02', 'active', '4.10.1', 0], ['009', 'srv-backup-01', 'active', '4.12.0', 0],
    ['010', 'pc-direction-01', 'pending', null, 3 * H]]
  for (const [id, name, status, version, since] of parc) {
    sql(stack, `insert into wazuh_agents (id, tenant_id, agent_id, name, ip, os_name, os_version, version, status, groups, node,
      last_keepalive, registered_at, last_event_at, status_since, updated_at) values (?, ${tenant}, ?, ?, ?, ?, ?, ?, ?, '["acme"]', 'worker-01', ?, ?, null, ?, ?)`,
      `shot-agent-${id}`, id, name, `10.20.0.${Number(id)}`, name.startsWith('pc') ? 'Windows' : 'Ubuntu', name.startsWith('pc') ? '11' : '24.04', version, status,
      status === 'active' ? ts(60e3) : ts(since), ts(60 * 24 * H), ts(since || 9 * 24 * H), ts(0))
    sql(stack, `insert into wazuh_agent_events (id, tenant_id, agent_id, status, previous, source, at) values (?, ${tenant}, ?, 'active', null, '', ?)`, `shot-ev-a-${id}`, id, ts(9 * 24 * H))
    if (status !== 'active') sql(stack, `insert into wazuh_agent_events (id, tenant_id, agent_id, status, previous, source, at) values (?, ${tenant}, ?, ?, 'active', '', ?)`, `shot-ev-b-${id}`, id, status, ts(since))
  }
  const b = await launch()
  const shot = async (p, path, name, after) => { await p.setViewportSize({ width, height: 900 }); await p.goto(`${BASE}${path}`); await p.waitForTimeout(1300); if (after) await after(p); await p.screenshot({ path: `${out}/${name}.png`, fullPage: true }) }
  const login0 = await b.newPage({ viewport: { width, height: 900 } }); await login0.goto(`${BASE}/`); await login0.waitForTimeout(800); await login0.screenshot({ path: `${out}/00-login.png` }); await login0.close()
  const m = await login(b, stack, 'manager')
  await shot(m, '/tickets', '10-liste'); await shot(m, '/kanban', '11-kanban'); await shot(m, '/pilotage', '12-pilotage'); await shot(m, '/rapports', '13-rapports')
  await shot(m, '/tickets/ACME-3', '14-ticket'); await shot(m, '/tickets/ACME-3', '14b-ticket-deplie', unfoldAll); await shot(m, '/mitre', '15-mitre'); await shot(m, '/audit', '16-audit-manager'); await shot(m, '/profil', '17-profil')
  await shot(m, '/tickets/ACME-3/rapport', '18-rapport-incident')
  await shot(m, '/parc?client=ACME&agent=002', '19-parc')
  const a = await login(b, stack, 'admin')
  for (const [p, n] of [['comptes', '20-admin-comptes'], ['clients', '21-admin-clients'], ['cles', '22-admin-cles'], ['mitre', '23-admin-mitre'], ['revue', '24-admin-revue'], ['audit', '25-admin-audit'], ['systeme', '26-admin-systeme']])
    await shot(a, `/admin/${p}`, n, p === 'clients' ? async (pg) => { await pg.getByRole('button', { name: 'Paramétrer' }).first().click(); await pg.waitForTimeout(400) } : p === 'comptes' ? async (pg) => { await pg.getByRole('button', { name: 'Nouveau compte' }).click(); await pg.waitForTimeout(300) } : undefined)
  const c = await login(b, stack, 'client')
  await shot(c, '/tickets', '30-client-liste'); await shot(c, '/tickets/ACME-3', '31-client-ticket')
  await b.close()
} finally { stack.stop() }
