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
  await kc('/admin/realms/soc/clients', { token: admin, method: 'POST', body: { clientId: 'keryx', secret: 'keryx-secret-e2e', publicClient: false, standardFlowEnabled: true, directAccessGrantsEnabled: false, redirectUris: [redirect], attributes: { 'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': `http://localhost:${PORT}/*`,
    // Déconnexion par le canal arrière (ADR-0017) : Keycloak prévient Keryx quand il ferme une session.
    'backchannel.logout.url': `http://localhost:${PORT}/api/v1/auth/oidc/soc/backchannel-logout`, 'backchannel.logout.session.required': 'true' } } })
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
  // Déconnexion décidée dans Keycloak (console d'administration) : Keycloak l'annonce à Keryx, qui ferme sa session.
  const me = () => again.p.evaluate(async () => (await fetch('/api/v1/me')).status)
  check(await me() === 200, 'SSO : session Keryx ouverte avant la déconnexion dans Keycloak')
  const kcUser = (await (await kc('/admin/realms/soc/users?username=analyste&exact=true', { token: admin })).json())[0]
  await kc(`/admin/realms/soc/users/${kcUser.id}/logout`, { token: admin, method: 'POST' })
  let statut = 0
  for (let i = 0; i < 40 && statut !== 401; i++) { statut = await me(); if (statut !== 401) await new Promise((r) => setTimeout(r, 250)) }
  check(statut === 401, `SSO : session fermée dans Keycloak, session Keryx fermée aussi (canal arrière, ${statut})`)
  await again.ctx.close()

  const bad = await signIn('client')
  await bad.p.waitForSelector('[role=alert]')
  check((await bad.p.locator('[role=alert]').innerText()).includes('Liaison refusée'), 'SSO : liaison refusée si le courriel vérifié ne correspond pas')
  check(await bad.p.locator('.sidebar').count() === 0, 'SSO : aucune session ouverte après un refus')
  await bad.ctx.close()
  if (stack.waf === 'blocage' && process.env.E2E_KC_PORT) {
    // Keycloak derrière le pare-feu applicatif : une injection dans le formulaire de connexion est refusée avant Keycloak.
    const r = await fetch(`${KC}/realms/soc/protocol/openid-connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'password', client_id: 'keryx', username: "admin' OR 1=1 --", password: '<script>alert(1)</script>' }) })
    check(r.status === 403, `SSO : pare-feu devant Keycloak, injection refusée (${r.status})`)
  }
  const unknown = await signIn('inconnu')
  await unknown.p.waitForSelector('[role=alert]')
  check((await unknown.p.locator('[role=alert]').innerText()).includes("Aucun compte Keryx"), 'SSO : compte Keryx inexistant refusé (jamais créé automatiquement)')
  await unknown.ctx.close()
}
