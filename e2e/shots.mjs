// Captures d'écran de tous les écrans principaux : node shots.mjs <dossier> [largeur]
import { mkdirSync } from 'node:fs'
import { BASE, launch, login, startStack, waitUp } from './harness.mjs'
const out = process.argv[2]; const width = Number(process.argv[3] || 1400)
mkdirSync(out, { recursive: true })
const stack = startStack()
try {
  await waitUp()
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) })
  const rules = [[7, 'ssh: échec de connexion répété depuis une source externe inconnue'], [10, 'web: tentative d’injection SQL détectée sur le portail client'], [12, 'fim: fichier système modifié'], [14, 'corrélation: exfiltration vers une IP externe']]
  for (let i = 0; i < 4; i++) await send({ id: `s${i}`, timestamp: new Date().toISOString(), rule: { id: String(5700 + i), level: rules[i][0], description: rules[i][1], groups: ['syslog', 'sshd'], mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } }, agent: { id: `00${i}`, name: `srv-prod-0${i}`, ip: `10.0.0.${i}`, labels: { importance: ['standard', 'sensible', 'vital', 'sensible'][i] } }, full_log: 'Nov 20 sshd[1]: Failed password for root' })
  const b = await launch()
  const shot = async (p, path, name, after) => { await p.setViewportSize({ width, height: 900 }); await p.goto(`${BASE}${path}`); await p.waitForTimeout(1300); if (after) await after(p); await p.screenshot({ path: `${out}/${name}.png`, fullPage: true }) }
  const login0 = await b.newPage({ viewport: { width, height: 900 } }); await login0.goto(`${BASE}/`); await login0.waitForTimeout(800); await login0.screenshot({ path: `${out}/00-login.png` }); await login0.close()
  const m = await login(b, stack, 'manager')
  await shot(m, '/tickets', '10-liste'); await shot(m, '/kanban', '11-kanban'); await shot(m, '/pilotage', '12-pilotage'); await shot(m, '/rapports', '13-rapports')
  await shot(m, '/tickets/ACME-3', '14-ticket'); await shot(m, '/mitre', '15-mitre'); await shot(m, '/audit', '16-audit-manager'); await shot(m, '/profil', '17-profil')
  await shot(m, '/tickets/ACME-3/rapport', '18-rapport-incident')
  const a = await login(b, stack, 'admin')
  for (const [p, n] of [['comptes', '20-admin-comptes'], ['clients', '21-admin-clients'], ['cles', '22-admin-cles'], ['mitre', '23-admin-mitre'], ['revue', '24-admin-revue'], ['audit', '25-admin-audit'], ['systeme', '26-admin-systeme']])
    await shot(a, `/admin/${p}`, n, p === 'clients' ? async (pg) => { await pg.getByRole('button', { name: 'Paramétrer' }).first().click(); await pg.waitForTimeout(400) } : p === 'comptes' ? async (pg) => { await pg.getByRole('button', { name: 'Nouveau compte' }).click(); await pg.waitForTimeout(300) } : undefined)
  const c = await login(b, stack, 'client')
  await shot(c, '/tickets', '30-client-liste'); await shot(c, '/tickets/ACME-3', '31-client-ticket')
  await b.close()
} finally { stack.stop() }
