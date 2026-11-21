// Scan de sécurité dynamique (OWASP ZAP) d'une instance de test, authentifiée en tant que manager.
// Usage : ZAP_HOME=/chemin/ZAP_2.16.1 node dast.mjs [minutes]   (auto-contrôle : ne remplace pas un test d'intrusion)
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { BASE, PASSWORD, startStack, totp, waitUp } from './harness.mjs'

const ZAP = process.env.ZAP_HOME || '/tmp/zap/ZAP_2.16.1'
const minutes = Number(process.argv[2] || 6)
const stack = startStack()
try {
  await waitUp()
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) })
  for (let i = 0; i < 3; i++) await send({ id: `d${i}`, timestamp: new Date().toISOString(), rule: { id: String(5700 + i), level: 10 + i, description: `règle d'essai ${i}`, groups: ['x'] }, agent: { id: `00${i}`, name: `srv-${i}`, ip: `10.0.0.${i}` }, full_log: 'x' })
  // session complète de manager (mot de passe + TOTP)
  const login = await fetch(`${BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'manager', password: PASSWORD }) })
  const stage = login.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
  const totpRes = await fetch(`${BASE}/api/v1/auth/totp`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: stage }, body: JSON.stringify({ code: totp(stack.seeds.manager.secret) }) })
  const cookies = Object.fromEntries(totpRes.headers.getSetCookie().map((c) => c.split(';')[0].split('=')))
  const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
  const csrf = (await totpRes.json()).csrf_token
  const plan = `
env:
  contexts:
    - name: keryx
      urls: ["${BASE}"]
      includePaths: ["${BASE}.*"]
      excludePaths: [".*/auth/logout.*", ".*/me/password.*", ".*/me/sessions.*", ".*/me/webauthn.*", ".*/admin/users/.*", ".*/auth/oidc/.*"]
  parameters: { failOnError: false, progressToStdout: true }
jobs:
  - type: openapi
    parameters: { apiUrl: "${BASE}/api/openapi.json", targetUrl: "${BASE}" }
  - type: replacer
    rules:
      - { description: cookie, matchType: req_header, matchString: Cookie, replacementString: "${cookie}", url: "${BASE}.*" }
      - { description: csrf, matchType: req_header, matchString: X-CSRF-Token, replacementString: "${csrf}", url: "${BASE}.*" }
  - type: spider
    parameters: { maxDuration: 2 }
  - type: passiveScan-wait
    parameters: { maxDuration: 3 }
  - type: activeScan
    parameters: { maxScanDurationInMins: ${minutes}, maxRuleDurationInMins: 1 }
  - type: report
    parameters: { template: traditional-json, reportDir: /tmp, reportFile: zap-keryx, reportTitle: Keryx }
`
  writeFileSync('/tmp/zap-plan.yaml', plan)
  const r = spawnSync(`${ZAP}/zap.sh`, ['-cmd', '-silent', '-autorun', '/tmp/zap-plan.yaml'], { encoding: 'utf8', timeout: (minutes + 12) * 60000 })
  console.log((r.stdout || '').split('\n').filter((l) => /Job |ERROR|Exception|alert|risk/i.test(l)).slice(-25).join('\n'))
  const rep = JSON.parse(readFileSync('/tmp/zap-keryx.json', 'utf8'))
  const alerts = rep.site.flatMap((s) => s.alerts)
  const byRisk = {}
  for (const a of alerts) (byRisk[a.riskdesc] ||= []).push(`${a.name} (${a.instances.length})`)
  console.log(JSON.stringify(byRisk, null, 1))
} finally { stack.stop() }
