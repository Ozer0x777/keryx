// Banc de test de parcours : base SQLite temporaire, serveur sur un port dédié, comptes de test, navigateur sans tête.
import { spawn, execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import { writeFileSync } from 'node:fs'
import { mkdtempSync, openSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const PY = process.env.KERYX_PYTHON || join(ROOT, '..', 'venv', 'bin', 'python')
export const PORT = Number(process.env.E2E_PORT || 8100)
export const BASE = `http://127.0.0.1:${PORT}`
export const PASSWORD = 'correct-horse-battery-staple'

// Autorité d'horodatage RFC 3161 locale (openssl ts), pour tester l'horodatage de bout en bout sans service externe.
export function startTsa(dir) {
  const sh = (cmd) => execFileSync('sh', ['-c', cmd], { cwd: dir, stdio: 'ignore' })
  sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Racine e2e" -days 30')
  sh('openssl req -newkey rsa:2048 -nodes -keyout tsa.key -out tsa.csr -subj "/CN=TSA e2e"')
  writeFileSync(`${dir}/ext.cnf`, 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\n')
  sh('openssl x509 -req -in tsa.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out tsa.pem -days 30 -extfile ext.cnf')
  writeFileSync(`${dir}/serial`, '01\n')
  writeFileSync(`${dir}/tsa.cnf`, `[tsa]\ndefault_tsa = t\n[t]\ndir = ${dir}\nserial = ${dir}/serial\ncrypto_device = builtin\nsigner_cert = ${dir}/tsa.pem\nsigner_key = ${dir}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_alg = sha256\n`)
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c)).on('end', () => {
      writeFileSync(`${dir}/q.tsq`, Buffer.concat(chunks))
      execFileSync('openssl', ['ts', '-reply', '-config', 'tsa.cnf', '-section', 't', '-queryfile', 'q.tsq', '-out', 'r.tsr'], { cwd: dir, stdio: 'ignore' })
      res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' }).end(readFileSync(`${dir}/r.tsr`))
    })
  })
  const port = 18000 + Math.floor(Math.random() * 1500)
  server.listen(port, '127.0.0.1')
  return { url: `http://127.0.0.1:${port}/tsa`, ca: `${dir}/ca.pem`, stop: () => server.close() }
}

// Faux indexeur Wazuh (tests/fake_indexer.py, le même que celui des tests pytest) : HTTPS local, autorité générée.
// `ready` donne son adresse, le fichier de son autorité et le compte de lecture attendu.
export function startIndexer(alertId) {
  const dir = mkdtempSync(join(tmpdir(), 'keryx-indexeur-'))
  const port = 19600 + Math.floor(Math.random() * 300)
  const proc = spawn(PY, [join(ROOT, 'tests', 'fake_indexer.py'), dir, String(port), alertId], { stdio: ['ignore', 'pipe', 'ignore'] })
  const ready = new Promise((resolve, reject) => {
    proc.stdout.once('data', (b) => resolve(JSON.parse(String(b).split('\n')[0])))
    proc.once('exit', () => reject(new Error('faux indexeur arrêté avant d\'être prêt')))
  })
  ready.catch(() => {})
  return { ready, stop: () => proc.kill('SIGTERM') }
}
export const WAZUH_ALERT_ID = 'e2e-wazuh-1'   // alerte du scénario « contexte Wazuh », connue du faux indexeur

// Faux VirusTotal (tests/fake_virustotal.py, le même que celui des tests pytest) : HTTP sur la boucle locale. Keryx y est
// envoyé par le réglage d'essai KERYX_VIRUSTOTAL_URL : rien ne part vers le vrai service. `ready` donne la clé d'API
// attendue et les empreintes connues du faux serveur.
export function startVirusTotal() {
  const port = 19920 + Math.floor(Math.random() * 60)
  const proc = spawn(PY, [join(ROOT, 'tests', 'fake_virustotal.py'), String(port)], { stdio: ['ignore', 'pipe', 'ignore'] })
  const ready = new Promise((resolve, reject) => {
    proc.stdout.once('data', (b) => resolve(JSON.parse(String(b).split('\n')[0])))
    proc.once('exit', () => reject(new Error('faux VirusTotal arrêté avant d\'être prêt')))
  })
  ready.catch(() => {})
  return { url: `http://127.0.0.1:${port}`, ready, stop: () => proc.kill('SIGTERM') }
}

export function startStack() {
  const dir = mkdtempSync(join(tmpdir(), 'keryx-e2e-'))
  const tsa = process.env.E2E_NO_TSA ? null : startTsa(mkdtempSync(join(tmpdir(), 'keryx-tsa-')))
  const indexer = startIndexer(WAZUH_ALERT_ID)
  const virustotal = startVirusTotal()
  const key = execFileSync(PY, ['-m', 'keryx.cli', 'gen-key'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  const env = { ...process.env, KERYX_SECRET_KEY: key, KERYX_DATABASE_URL: `sqlite:///${dir}/e2e.db`, KERYX_ATTACHMENTS_DIR: `${dir}/pj`, KERYX_COOKIE_SECURE: 'false', KERYX_PUBLIC_URL: `http://localhost:${PORT}`, KERYX_LOGIN_IP_LIMIT: '1000', ...(tsa ? { KERYX_TSA_URL: tsa.url, KERYX_TSA_CA_FILE: tsa.ca } : {}), ...(process.env.E2E_KEYCLOAK ? { KERYX_OIDC_ALLOW_HTTP: 'true', KERYX_OIDC_PROVIDERS: JSON.stringify([{ name: 'soc', label: 'Compte SOC', issuer: `${process.env.E2E_KEYCLOAK}/realms/soc`, client_id: 'keryx', client_secret: 'keryx-secret-e2e' }]) } : {}), KERYX_LOGIN_USER_LIMIT: '1000', KERYX_WAZUH_ALLOW_LOOPBACK: 'true', KERYX_VIRUSTOTAL_URL: virustotal.url, KERYX_VIRUSTOTAL_ALLOW_LOOPBACK: 'true', KERYX_VIRUSTOTAL_USER_LIMIT: '30', KERYX_VIRUSTOTAL_CLIENT_LIMIT: '60', PYTHONWARNINGS: 'ignore' }
  const cli = (...args) => execFileSync(PY, ['-m', 'keryx.cli', ...args], { cwd: ROOT, env: { ...env, KERYX_NEW_PASSWORD: PASSWORD }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
  execFileSync(PY, ['-m', 'alembic', 'upgrade', 'head'], { cwd: ROOT, env, stdio: 'ignore' })
  const seeds = {}
  cli('add-client', 'ACME', 'Acme Industrie'); cli('add-client', 'DELTA', 'Transports Delta')
  for (const [name, role, clients] of [['admin', 'admin', ''], ['manager', 'manager', 'ACME,DELTA'], ['analyste', 'analyst', 'ACME'], ['client', 'client', 'ACME']]) {
    const out = cli('add-user', name, `Test ${name}`, role, ...(clients ? ['--clients', clients] : []))
    seeds[name] = { secret: /secret=([A-Z2-7]+)/.exec(out)[1], recovery: [...out.matchAll(/^\s+([0-9a-f]{6}-[0-9a-f]{6})$/gm)].map((m) => m[1]) }
  }
  seeds.apiKey = /(kx_[\w-]+)/.exec(cli('add-api-key', 'ACME', 'wazuh-e2e'))[1]
  const server = spawn(PY, ['-m', 'uvicorn', 'keryx.api:create_app', '--factory', '--port', String(PORT)], { cwd: ROOT, env, stdio: ['ignore', openSync(`${dir}/server.log`, 'a'), openSync(`${dir}/server.log`, 'a')] })
  return { dir, seeds, server, indexer, virustotal, stop: () => { server.kill('SIGTERM'); tsa?.stop(); indexer.stop(); virustotal.stop() } }
}

// Requête SQL directe sur la base de test (préparation de données que l'interface ne propose pas).
export const sql = (stack, statement, ...params) => execFileSync(PY, ['-c', 'import sqlite3,sys,json;c=sqlite3.connect(sys.argv[1]);c.execute(sys.argv[2], json.loads(sys.argv[3]));c.commit()', `${stack.dir}/e2e.db`, statement, JSON.stringify(params)], { stdio: 'ignore' })

export const totp = (secret) => execFileSync(PY, ['-c', `import pyotp;print(pyotp.TOTP('${secret}').now())`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()

export async function waitUp() {
  for (let i = 0; i < 60; i++) { try { if ((await fetch(`${BASE}/healthz`)).ok) return } catch { /* pas prêt */ } await new Promise((r) => setTimeout(r, 250)) }
  throw new Error('serveur non démarré')
}

export async function launch() {
  return chromium.launch({ executablePath: process.env.CHROME_PATH || '/opt/google/chrome/chrome', args: ['--no-sandbox'] })
}

export const lastStep = {}   // dernier pas TOTP utilisé par compte (un code ne sert qu une fois)
export async function login(browser, stack, name) {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } })
  const page = await ctx.newPage()
  page.errors = []
  page.on('pageerror', (e) => page.errors.push(e.message))
  page.on('console', (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) page.errors.push(`CSP : ${m.text().slice(0, 160)}`) })   // une violation de CSP est une erreur
  await page.goto(`${BASE}/`)
  await page.locator('input').first().fill(name)
  await page.locator('input[type=password]').fill(PASSWORD)
  await page.getByRole('button').first().click()
  await page.waitForTimeout(1200)
  // Un code TOTP ne sert qu'une fois par pas de 30 s : attendre le pas suivant si ce compte vient de l'utiliser.
  const cur = Math.floor(Date.now() / 30000)
  if (lastStep[name] >= cur) await new Promise((r) => setTimeout(r, (lastStep[name] + 1) * 30000 - Date.now() + 500))
  const code = totp(stack.seeds[name].secret)                 // génération (≈ 0,2 s) AVANT de noter le pas : jamais en dessous du pas réel
  lastStep[name] = Math.floor(Date.now() / 30000)
  await page.locator('input').first().fill(code)
  await page.getByRole('button').first().click()
  try { await page.waitForSelector('.sidebar', { timeout: 8000 }) } catch (e) {
    console.error(`connexion de « ${name} » impossible. Page : ${(await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 300)}`)
    try { console.error(readFileSync(`${stack.dir}/server.log`, 'utf8').split('\n').filter((l) => l.includes('/auth/') || l.includes('/me')).slice(-12).join('\n')) } catch { /* journal absent */ }
    throw e
  }
  return page
}

// Dialogue de confirmation ou de saisie de l'interface (<dialog> natif, plus de window.prompt / confirm) :
// remplit les champs par leur attribut name, puis valide avec le bouton d'action (ou annule).
export async function answerDialog(page, values = {}, { cancel = false, stays = false } = {}) {
  const d = page.locator('dialog[open]')
  await d.waitFor()
  for (const [name, value] of Object.entries(values)) await d.locator(`[name="${name}"]`).fill(value)
  await d.locator(cancel ? 'button[data-cancel]' : 'button[type=submit]').click()
  if (!stays) await d.waitFor({ state: 'detached' })
  return d
}

// Fiche ticket : les panneaux sont repliables (<details>) et repliés ou non selon la phase du ticket.
// unfold() déplie un panneau par son titre comme le ferait l'utilisateur ; unfoldAll() les déplie tous (contrôles
// qui portent sur tout le contenu de la page : traduction, accessibilité, mise en page).
export async function unfold(page, title) {
  const d = page.locator(`section[aria-label="${title}"] > details`)
  await d.waitFor({ state: 'attached' })
  // La fiche ticket de l'équipe est en onglets (ADR-0026) : on active d'abord celui qui contient le panneau.
  const tab = await d.evaluate((e) => { const p = e.closest('[role=tabpanel]'); return p && p.hidden ? p.getAttribute('aria-labelledby') : null })
  if (tab) await page.locator(`#${tab}`).click()
  if (!(await d.evaluate((e) => e.open))) await d.locator('> summary').click()
}
export async function unfoldAll(page) {
  // Contrôles qui portent sur toute la page : les panneaux de tous les onglets sont rendus visibles (un état du
  // composant qui changerait l'onglet les cacherait de nouveau ; ces contrôles n'en provoquent pas).
  await page.evaluate(() => document.querySelectorAll('[role=tabpanel][hidden]').forEach((p) => { p.hidden = false }))
  const closed = page.locator('.fold > details:not([open]) > summary')
  for (let i = 0; i < 40 && await closed.count() > 0; i++) await closed.first().click()   // la liste raccourcit à chaque clic
}
export function check(cond, label) {
  if (!cond) { console.error(`✗ ${label}`); process.exitCode = 1 } else console.log(`✓ ${label}`)
}

// Attente active sans évaluation de script dans la page (la CSP de Keryx l'interdit).
// Comme until, mais renvoie vrai ou faux au lieu de lever : pour un check() sur un état qui suit un rendu
// (l'URL change avant que React ait repeint, surtout sur une machine lente).
export async function eventually(fn, ms = 5000) {
  const end = Date.now() + ms
  while (Date.now() < end) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 100)) }
  return !!(await fn())
}

export async function until(fn, label = 'condition', ms = 8000) {
  const end = Date.now() + ms
  while (Date.now() < end) { if (await fn()) return; await new Promise((r) => setTimeout(r, 150)) }
  throw new Error(`délai dépassé : ${label}`)
}
