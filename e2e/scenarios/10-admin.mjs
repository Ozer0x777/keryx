import { answerDialog } from '../harness.mjs'

export default async ({ browser, stack, BASE, check, login }) => {
  const p = await login('admin')
  await p.waitForSelector('text=Administration')
  check(p.url().endsWith('/admin/comptes'), 'admin arrive sur Comptes')
  // créer un client puis un compte analyste
  await p.getByRole('link', { name: 'Clients' }).click()
  await p.fill('input[name=key]', 'NOVA'); await p.fill('input[name=name]', 'Nova SA'); await p.getByRole('button', { name: 'Ajouter' }).click()
  await p.waitForSelector('text=Nova SA')
  check(true, 'client créé depuis l\'interface')
  await p.getByRole('link', { name: 'Comptes', exact: true }).click()
  await p.getByRole('button', { name: 'Nouveau compte' }).click()
  await p.fill('input[name=username]', 'nouvel.analyste'); await p.fill('input[name=display_name]', 'Nouvel Analyste')
  await p.check('input[name=clients][value=NOVA]'); await p.fill('input[name=password]', 'un-mot-de-passe-solide')
  await p.getByRole('button', { name: 'Créer' }).click()
  await p.waitForSelector('.onetime code')
  stack.activation = (await p.locator('.onetime code').innerText()).trim()   // sans SMTP, l'Admin transmet ce code hors bande
  check(/^[A-Za-z0-9_-]{16,}$/.test(stack.activation), "code d'activation à usage unique remis à l'Admin (encart des secrets à usage unique)")
  check(await p.locator('.onetime dt').count() === 1 && (await p.locator('.onetime dt').innerText()).startsWith("Code d'activation"), 'aucun secret TOTP montré à l\'Admin (seul le code d\'activation)')
  check(!(await p.locator('.live').innerText()).includes(stack.activation), "le code n'est pas recopié dans le message de statut")
  await p.getByRole('button', { name: "J'ai noté ces valeurs" }).click()
  check(await p.locator('.onetime').count() === 0, "le code d'activation disparaît une fois noté")
  const row = p.locator('tr', { hasText: 'nouvel.analyste' })
  check(await row.locator('text=À activer').count() === 1, 'compte marqué « À activer »')
  // mot de passe d'un compte : champs masqués, confirmation, erreur en ligne, Échap rend le focus
  const pwd = row.getByRole('button', { name: 'Mot de passe' })
  await pwd.click()
  const d = await answerDialog(p, { password: 'un-autre-mot-de-passe', confirm: 'pas-le-meme' }, { stays: true })
  check(await d.locator('input[type=password]').count() === 2 && await d.locator('input:not([type=password])').count() === 0, 'mot de passe : deux champs masqués (saisie et confirmation)')
  check((await d.locator('.field-error').innerText()).includes('ne correspondent pas'), 'mot de passe : écart signalé sous le champ de confirmation')
  await p.keyboard.press('Escape'); await d.waitFor({ state: 'detached' })
  check(await pwd.evaluate((e) => e === document.activeElement), 'mot de passe : Échap ferme le dialogue et rend le focus au bouton')
  // clé d'API
  await p.getByRole('link', { name: "Clés d'API" }).click()
  await p.waitForSelector('text=wazuh-e2e')
  check(await p.locator('.pill.ok', { hasText: 'Active' }).count() > 0, 'clé neuve : active, pas signalée muette avant 24 h')
  // système
  await p.getByRole('link', { name: 'État du système' }).click()
  await p.waitForSelector('text=Base de données')
  check(await p.locator('text=Antivirus').count() > 0, 'état du système affiché')
  // audit
  await p.getByRole('link', { name: "Journal d'audit" }).click()
  await p.getByRole('button', { name: 'Vérifier la chaîne' }).click()
  await p.waitForSelector('.banner.ok')
  check(true, 'chaîne d\'audit vérifiée depuis l\'interface')
  check(p.errors.length === 0, 'aucune erreur JavaScript')
  await p.context().close()
}
