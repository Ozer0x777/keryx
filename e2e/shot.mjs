// Capture d'écran d'une page pour un rôle : node shot.mjs <rôle> <chemin> <fichier.png>
import { BASE, launch, login, startStack, waitUp } from './harness.mjs'
const [role, path, out] = process.argv.slice(2)
const stack = startStack()
try {
  await waitUp()
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) })
  for (let i = 0; i < 4; i++) await send({ id: `s${i}`, timestamp: new Date().toISOString(), rule: { id: String(5700 + i), level: [7, 10, 12, 14][i], description: ['ssh: échec de connexion', 'web: injection SQL', 'fim: fichier modifié', 'corrélation: exfiltration'][i], groups: ['x'] }, agent: { id: `00${i}`, name: `srv-${i}`, ip: `10.0.0.${i}` }, full_log: 'x' })
  const b = await launch()
  const p = await login(b, stack, role)
  await p.goto(`${BASE}${path}`); await p.waitForTimeout(1500)
  await p.screenshot({ path: out, fullPage: true })
  await b.close()
} finally { stack.stop() }
