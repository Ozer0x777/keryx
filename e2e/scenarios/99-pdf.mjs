import { readFileSync } from 'node:fs'

// PDF produits par le serveur (ADR-0036) : chaque page de rapport propose « Télécharger le PDF ».
export default async ({ BASE, check, login, stack }) => {
  const send = (a) => fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(a) }).then((r) => r.json())
  const ref = (await send({ timestamp: new Date().toISOString(), id: 'pdf1', rule: { id: '100990', level: 10, description: 'pdf : rapport', groups: ['t'] }, agent: { id: '099', name: 'srv-pdf', ip: '10.20.9.9' }, full_log: 'x' })).ticket
  const m = await login('manager')
  const telecharge = async (path, label) => {
    await m.goto(`${BASE}${path}`)
    const bouton = m.getByRole('button', { name: 'Télécharger le PDF' })
    await bouton.waitFor()
    const [dl] = await Promise.all([m.waitForEvent('download'), bouton.click()])
    const debut = readFileSync(await dl.path()).subarray(0, 5).toString()
    check(debut === '%PDF-' && dl.suggestedFilename().endsWith('.pdf'), `PDF du serveur : ${label} (${dl.suggestedFilename()})`)
  }
  await telecharge('/rapports?client=ACME', 'rapport périodique')
  await telecharge(`/tickets/${ref}/rapport`, "rapport d'incident")
  await telecharge(`/tickets/${ref}/point-situation`, 'point de situation')
  await telecharge(`/tickets/${ref}/rapport-analyse`, "rapport d'analyse")
  const c = await login('client')
  await c.goto(`${BASE}/rapports`)
  const [dl] = await Promise.all([c.waitForEvent('download'), c.getByRole('button', { name: 'Télécharger le PDF' }).click()])
  check(readFileSync(await dl.path()).subarray(0, 5).toString() === '%PDF-', 'PDF du serveur : rapport du client')
  check(m.errors.length === 0 && c.errors.length === 0, 'aucune erreur JavaScript')
}
