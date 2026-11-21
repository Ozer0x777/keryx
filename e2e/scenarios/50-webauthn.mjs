// Clé de sécurité WebAuthn (authentificateur virtuel de Chrome) : enregistrement, connexion sans TOTP, retrait.
import { PASSWORD, PORT, answerDialog, lastStep, totp } from '../harness.mjs'

export default async ({ browser, stack, check }) => {
  const BASE = `http://localhost:${PORT}`          // l'identifiant de partie de confiance est « localhost »
  const ctx = await browser.newContext({ viewport: { width: 1300, height: 900 } })
  const p = await ctx.newPage()
  p.errors = []; p.on('pageerror', (e) => p.errors.push(e.message))
  const cdp = await ctx.newCDPSession(p)
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })

  const signInPassword = async () => {
    await p.goto(`${BASE}/`)
    await p.locator('input').first().fill('client')
    await p.locator('input[type=password]').fill(PASSWORD)
    await p.getByRole('button', { name: 'Continuer' }).click()
    await p.waitForTimeout(1000)
  }
  await signInPassword()
  await new Promise((r) => setTimeout(r, 31000 - (Date.now() % 30000)))        // pas TOTP encore inutilisé pour ce compte
  lastStep.client = Math.floor(Date.now() / 30000)
  await p.locator('input').first().fill(totp(stack.seeds.client.secret))
  await p.getByRole('button', { name: 'Vérifier' }).click()
  await p.waitForSelector('.sidebar')

  await p.goto(`${BASE}/profil`)
  await p.waitForSelector('text=Clés de sécurité (WebAuthn)')
  await p.fill('input[name=name]', 'Clé de test'); await p.locator('section[aria-label="Clés de sécurité"] input[name=password]').fill(PASSWORD)
  await p.getByRole('button', { name: 'Ajouter une clé' }).click()
  await p.waitForSelector('text=Clé de sécurité enregistrée.')
  check(await p.locator('.found li', { hasText: 'Clé de test' }).count() === 1, 'clé enregistrée et listée dans le profil')

  await p.getByRole('button', { name: 'Se déconnecter' }).click()
  await p.waitForSelector('text=Connexion')
  await signInPassword()
  await p.waitForSelector('text=Utiliser ma clé de sécurité')
  await p.getByRole('button', { name: 'Utiliser ma clé de sécurité' }).click()
  await p.waitForSelector('.sidebar', { timeout: 10000 })
  check(true, 'connexion avec la clé de sécurité, sans code TOTP')

  await p.goto(`${BASE}/profil`)
  await p.waitForSelector('.found li >> text=utilisée le')
  check(true, 'dernière utilisation de la clé tracée')
  await p.getByRole('button', { name: 'Retirer' }).click()
  await answerDialog(p)
  await p.waitForSelector('.found', { state: 'detached' })
  check(true, 'clé retirée')
  check(p.errors.length === 0, 'aucune erreur JavaScript')
  await ctx.close()
}
