import { answerDialog, until } from '../harness.mjs'

export default async ({ stack, BASE, check, login }) => {
  const m = await login('manager')
  // mode crise
  await m.goto(`${BASE}/tickets/ACME-1`)
  await m.getByRole('button', { name: 'Ouvrir le mode crise' }).click()
  await answerDialog(m, { reason: 'exfiltration suspectée' })
  await m.waitForSelector('.head-tags .pill.danger >> text=CRISE')   // étiquette « CRISE » dans l'en-tête de la fiche
  check(true, 'mode crise ouvert, étiquette CRISE visible')
  await m.fill('textarea[name=body]', 'Isoler srv-web-01 du réseau <script>alert(1)</script>')
  await m.getByRole('button', { name: 'Ajouter au registre' }).click()
  await m.waitForSelector('.crisis-text')
  check((await m.locator('.crisis-text').first().innerText()).includes('<script>'), 'texte de crise affiché tel quel, non interprété')
  await m.selectOption('.crisis select', 'action')
  await m.fill('textarea[name=body]', 'Réinitialiser les mots de passe'); await m.fill('input[name=owner]', 'analyste')
  await m.getByRole('button', { name: 'Ajouter au registre' }).click()
  await m.waitForSelector('.crisis-list input[type=checkbox]')
  await m.click('.crisis-list input[type=checkbox]')
  await until(async () => (await m.locator('.crisis-list li.done').count()) === 1, 'action cochée')
  check(true, 'action du plan cochée')
  await m.goto(`${BASE}/tickets`)
  await m.waitForSelector('tbody .pill >> text=CRISE')
  check(await m.locator('.pill', { hasText: 'CRISE' }).count() === 1, 'ticket marqué CRISE dans la liste')
  // journal d'audit du manager
  await m.getByRole('link', { name: "Journal d'audit" }).click()
  await m.waitForSelector('text=ticket.crise_ouverte')
  check(true, 'le manager consulte le journal de ses clients')
  check(m.errors.length === 0, 'aucune erreur JavaScript (manager)')
  await m.context().close()

  // l'admin voit le journal mais pas le contenu des tickets
  const a = await login('admin')
  await a.getByRole('link', { name: "Journal d'audit" }).click()
  await a.waitForSelector('text=Consulter le journal')
  await a.fill('input[placeholder="ex. ticket."]', 'ticket.'); await a.getByRole('button', { name: 'Filtrer' }).click()
  await a.waitForSelector('.pill >> text=masqué')
  check(await a.locator('text=exfiltration suspectée').count() === 0, 'contenu des tickets masqué pour l\'admin')
  await a.getByRole('button', { name: 'Générer' }).click()
  await a.waitForSelector('text=/^\\d+:[0-9a-f]{64}$/')
  check(true, 'point de contrôle généré')
  await a.getByRole('link', { name: 'État du système' }).click()
  await a.getByRole('button', { name: 'Simuler' }).click()
  await a.waitForSelector('text=Simulation')
  check(true, 'simulation de rétention')
  await a.getByRole('link', { name: 'MITRE' }).click()
  const stix = { type: 'bundle', objects: [{ type: 'attack-pattern', name: 'Brute Force', external_references: [{ source_name: 'mitre-attack', external_id: 'T1110' }], kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'credential-access' }] }] }
  await a.setInputFiles('input[type=file]', { name: 'attack.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(stix)) })
  await a.waitForSelector('text=1 technique(s) ajoutée(s)')
  check(true, 'import STIX depuis l\'interface')
  check(a.errors.length === 0, 'aucune erreur JavaScript (admin)')
  await a.context().close()
}
