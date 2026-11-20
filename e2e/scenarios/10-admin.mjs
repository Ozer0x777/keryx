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
  await p.waitForSelector('text=activera lui-même sa double authentification')
  check(await p.locator('.onetime').count() === 0, 'aucun secret TOTP montré à l\'Admin')
  check(await p.locator('tr', { hasText: 'nouvel.analyste' }).locator('text=À activer').count() === 1, 'compte marqué « À activer »')
  // clé d'API
  await p.getByRole('link', { name: "Clés d'API" }).click()
  await p.waitForSelector('text=wazuh-e2e')
  check(await p.locator('.pill.warn', { hasText: 'Muette' }).count() > 0, 'source muette signalée')
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
