// SSO OIDC contre un vrai Keycloak (E2E_KEYCLOAK=http://localhost:8180). Ignoré si Keycloak n'est pas lancé.
import { PORT, sql } from '../harness.mjs'

const KC = process.env.E2E_KEYCLOAK
const kc = async (path, { token, method = 'GET', body, form } = {}) => {
  const r = await fetch(`${KC}${path}`, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: form ? new URLSearchParams(form) : body ? JSON.stringify(body) : undefined })
  if (!r.ok && r.status !== 404) throw new Error(`Keycloak ${method} ${path} : ${r.status} ${await r.text()}`)
  return r
}

export default async ({ browser, stack, check }) => {
  if (!KC) { console.log('  (ignoré : E2E_KEYCLOAK non défini)'); return }
  const admin = (await (await kc('/realms/master/protocol/openid-connect/token', { method: 'POST', form: { grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin-pass-123' } })).json()).access_token
  await kc('/admin/realms/soc', { token: admin, method: 'DELETE' })
  await kc('/admin/realms', { token: admin, method: 'POST', body: { realm: 'soc', enabled: true, sslRequired: 'none', registrationAllowed: false } })
  const redirect = `http://localhost:${PORT}/api/v1/auth/oidc/soc/callback`
  await kc('/admin/realms/soc/clients', { token: admin, method: 'POST', body: { clientId: 'keryx', secret: 'keryx-secret-e2e', publicClient: false, standardFlowEnabled: true, directAccessGrantsEnabled: false, redirectUris: [redirect], attributes: { 'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': `http://localhost:${PORT}/*` } } })
  const mkUser = (username, email, verified) => kc('/admin/realms/soc/users', { token: admin, method: 'POST', body: { username, email, emailVerified: verified, enabled: true, firstName: 'Sso', lastName: username, credentials: [{ type: 'password', value: 'Sso-Pass-12345!', temporary: false }] } })
  await mkUser('analyste', 'analyste@keryx.test', true)          // même identifiant que le compte Keryx « analyste », courriel vérifié et identique
  await mkUser('client', 'pirate@evil.test', true)               // même identifiant que « client », mais courriel différent : liaison refusée
  await mkUser('inconnu', 'inconnu@keryx.test', true)            // aucun compte Keryx
  sql(stack, "update users set email = ? where username = 'analyste'", 'analyste@keryx.test')
  sql(stack, "update users set email = ? where username = 'client'", 'client@keryx.test')

  const BASE = `http://localhost:${PORT}`
  const signIn = async (username) => {
    const ctx = await browser.newContext({ viewport: { width: 1300, height: 900 } })
    const p = await ctx.newPage()
    p.errors = []; p.on('pageerror', (e) => p.errors.push(e.message))
    await p.goto(`${BASE}/`)
    await p.getByRole('link', { name: /Compte SOC/ }).click()
    await p.waitForSelector('#username')
    await p.fill('#username', username); await p.fill('#password', 'Sso-Pass-12345!')
    await p.click('#kc-login')
    await p.waitForURL(`${BASE}/**`, { timeout: 15000 })
    return { ctx, p }
  }

  const ok = await signIn('analyste')
  await ok.p.waitForSelector('.sidebar', { timeout: 10000 })
  check(await ok.p.locator('.sidebar', { hasText: 'Test analyste' }).count() === 1, 'SSO : connexion via Keycloak, sans mot de passe ni TOTP Keryx')
  check(await ok.p.locator('.nav-link', { hasText: 'Tickets' }).count() === 1, 'SSO : rôle et clients Keryx appliqués')
  check(ok.p.errors.length === 0, 'SSO : aucune erreur JavaScript')
  // Déconnexion unique : Keryx ferme aussi la session Keycloak (une nouvelle connexion SSO redemande le mot de passe)
  await ok.p.getByRole('button', { name: 'Se déconnecter' }).click()
  await ok.p.waitForURL(`${BASE}/connexion`, { timeout: 15000 })
  await ok.p.waitForSelector('h1:has-text("Connexion")', { timeout: 15000 })
  check(true, 'SSO : déconnexion unique, retour sur la page de connexion Keryx')
  await ok.p.getByRole('link', { name: /Compte SOC/ }).click()
  try { await ok.p.waitForSelector('#username', { timeout: 10000 }) } catch (e) { console.error('URL après clic SSO :', ok.p.url(), '|', (await ok.p.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 200)); throw e }
  check(true, 'SSO : la session Keycloak est fermée (identifiants redemandés)')
  await ok.ctx.close()
  const again = await signIn('analyste')           // 2e connexion : reconnu par « sub »
  await again.p.waitForSelector('.sidebar', { timeout: 10000 })
  check(true, 'SSO : deuxième connexion (identité déjà liée)')
  await again.ctx.close()

  const bad = await signIn('client')
  await bad.p.waitForSelector('[role=alert]')
  check((await bad.p.locator('[role=alert]').innerText()).includes('Liaison refusée'), 'SSO : liaison refusée si le courriel vérifié ne correspond pas')
  check(await bad.p.locator('.sidebar').count() === 0, 'SSO : aucune session ouverte après un refus')
  await bad.ctx.close()
  const unknown = await signIn('inconnu')
  await unknown.p.waitForSelector('[role=alert]')
  check((await unknown.p.locator('[role=alert]').innerText()).includes("Aucun compte Keryx"), 'SSO : compte Keryx inexistant refusé (jamais créé automatiquement)')
  await unknown.ctx.close()
}
