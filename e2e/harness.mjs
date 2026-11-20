// Banc de test de parcours : base SQLite temporaire, serveur sur un port dédié, comptes de test, navigateur sans tête.
import { spawn, execFileSync } from 'node:child_process'
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

export function startStack() {
  const dir = mkdtempSync(join(tmpdir(), 'keryx-e2e-'))
  const key = execFileSync(PY, ['-m', 'keryx.cli', 'gen-key'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  const env = { ...process.env, KERYX_SECRET_KEY: key, KERYX_DATABASE_URL: `sqlite:///${dir}/e2e.db`, KERYX_ATTACHMENTS_DIR: `${dir}/pj`, KERYX_COOKIE_SECURE: 'false', KERYX_PUBLIC_URL: `http://localhost:${PORT}`, KERYX_LOGIN_IP_LIMIT: '1000', ...(process.env.E2E_KEYCLOAK ? { KERYX_OIDC_ALLOW_HTTP: 'true', KERYX_OIDC_PROVIDERS: JSON.stringify([{ name: 'soc', label: 'Compte SOC', issuer: `${process.env.E2E_KEYCLOAK}/realms/soc`, client_id: 'keryx', client_secret: 'keryx-secret-e2e' }]) } : {}), KERYX_LOGIN_USER_LIMIT: '1000', PYTHONWARNINGS: 'ignore' }
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
  return { dir, seeds, server, stop: () => server.kill('SIGTERM') }
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
  await page.goto(`${BASE}/`)
  await page.locator('input').first().fill(name)
  await page.locator('input[type=password]').fill(PASSWORD)
  await page.getByRole('button').first().click()
  await page.waitForTimeout(1200)
  // Un code TOTP ne sert qu'une fois par pas de 30 s : attendre le pas suivant si ce compte vient de l'utiliser.
  const cur = Math.floor(Date.now() / 30000)
  if (lastStep[name] >= cur) await new Promise((r) => setTimeout(r, (lastStep[name] + 1) * 30000 - Date.now() + 500))
  lastStep[name] = Math.floor(Date.now() / 30000)
  await page.locator('input').first().fill(totp(stack.seeds[name].secret))
  await page.getByRole('button').first().click()
  try { await page.waitForSelector('.sidebar', { timeout: 8000 }) } catch (e) {
    console.error(`connexion de « ${name} » impossible. Page : ${(await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 300)}`)
    try { console.error(readFileSync(`${stack.dir}/server.log`, 'utf8').split('\n').filter((l) => l.includes('/auth/') || l.includes('/me')).slice(-12).join('\n')) } catch { /* journal absent */ }
    throw e
  }
  return page
}

export function check(cond, label) {
  if (!cond) { console.error(`✗ ${label}`); process.exitCode = 1 } else console.log(`✓ ${label}`)
}

// Attente active sans évaluation de script dans la page (la CSP de Keryx l'interdit).
export async function until(fn, label = 'condition', ms = 8000) {
  const end = Date.now() + ms
  while (Date.now() < end) { if (await fn()) return; await new Promise((r) => setTimeout(r, 150)) }
  throw new Error(`délai dépassé : ${label}`)
}
