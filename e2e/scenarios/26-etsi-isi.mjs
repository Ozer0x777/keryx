// Classification ETSI GS ISI 002 et export IODEF 2.0 depuis l'interface.
import { unfold } from '../harness.mjs'

export default async ({ BASE, check, login }) => {
  const m = await login('manager')
  await m.goto(`${BASE}/tickets/ACME-1`)
  const panel = m.locator('section[aria-label="Classification ETSI ISI"]')
  await panel.waitFor()
  await unfold(m, 'Classification ETSI ISI')   // replié par défaut tant que le ticket n'est pas en réponse
  check(await panel.locator('legend').count() === 1, 'panneau ETSI ISI affiché dans la fiche ticket')
  await panel.getByLabel('Catégorie').selectOption('IEX')
  await panel.getByLabel(/Qui et\/ou pourquoi/).first().selectOption('malicious_act')
  await panel.getByLabel(/^Quoi/).first().selectOption('unauthorized_access')
  await panel.getByLabel(/Statut de l'incident/).first().selectOption('underway')
  await panel.getByLabel(/Type de cible/).first().selectOption('systems')
  await panel.getByRole('checkbox').first().check()
  await panel.getByRole('button', { name: 'Enregistrer' }).click()
  await m.waitForSelector('text=Classification ETSI ISI enregistrée.')
  check(true, 'classification enregistrée')
  const [dl] = await Promise.all([m.waitForEvent('download'), panel.getByRole('button', { name: /Exporter \(IODEF 2.0/ }).click()])
  check(dl.suggestedFilename().endsWith('-etsi-isi.json'), 'export IODEF ETSI ISI téléchargé')
  check(m.errors.length === 0, 'aucune erreur JavaScript')
  await m.context().close()
}
