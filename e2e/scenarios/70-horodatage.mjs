// Horodatage RFC 3161 d'une pièce et du point de contrôle d'audit, via l'autorité locale du banc de test.
import { PASSWORD, PORT, unfold } from '../harness.mjs'
import { writeFileSync } from 'node:fs'

export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  await m.goto(`${BASE}/tickets/ACME-1`)
  await m.waitForSelector('text=Registre des preuves')
  await unfold(m, 'Registre des preuves')
  // dépôt d'une petite archive ZIP
  writeFileSync('/tmp/e2e-preuve.zip', Buffer.from('504b0506000000000000000000000000000000000000', 'hex'))
  await m.getByRole('button', { name: /Déposer un fichier/ }).click()
  await m.setInputFiles('input[type=file][name=file]', '/tmp/e2e-preuve.zip')
  await m.fill('input[name=description]', 'Journal exporté'); await m.fill('input[name=method]', 'export manuel')
  await m.getByRole('button', { name: 'Déposer', exact: true }).click()
  await m.waitForSelector('text=Journal exporté')
  await m.getByRole('button', { name: 'Horodater (RFC 3161)' }).click()
  await m.waitForSelector('.stamps .pill.ok')
  check(true, 'pièce horodatée par l\'autorité')
  await m.getByRole('button', { name: 'Vérifier' }).first().click()
  await m.waitForSelector('text=Jeton valide')
  check(true, 'jeton revérifié (signature et chaîne)')
  const [dl] = await Promise.all([m.waitForEvent('download'), m.getByRole('button', { name: 'Jeton .tsr' }).click()])
  check(dl.suggestedFilename().endsWith('.tsr'), 'jeton téléchargeable')
  check(m.errors.length === 0, 'aucune erreur JavaScript')
  await m.context().close()
  const a = await login('admin')
  await a.goto(`${BASE}/admin/audit`)
  await a.getByRole('button', { name: 'Horodater le point de contrôle actuel' }).click()
  await a.waitForSelector('text=horodaté (série')
  check(true, 'point de contrôle de l\'audit horodaté')
  await a.context().close()
}
