// Contexte Wazuh (ADR-0021) : réglage d'un client par l'Admin, lien vers l'alerte et lecture de l'indexeur sur la fiche,
// conservation comme preuve, et rien de tout cela pour le client. L'indexeur est le faux indexeur local
// (tests/fake_indexer.py) : ce parcours ne prouve pas la compatibilité avec un vrai Wazuh.
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { answerDialog, unfold, until, WAZUH_ALERT_ID } from '../harness.mjs'
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')

const axe = async (page) => {
  await page.evaluate(axeSource)  // eslint-disable-line
  return page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })).violations
    .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0].target.join(' '), help: v.help })))
}
const csrf = async (page) => (await page.context().cookies()).find((c) => c.name === 'keryx_csrf').value
const DASHBOARD = "https://wazuh.exemple/app/data-explorer/discover#?_q=(query:(language:kuery,query:'id:%22{alert_id}%22'))&_g=(time:(from:'{from}',to:'{to}'))"

export default async ({ stack, BASE, check, login }) => {
  const idx = await stack.indexer.ready
  const alert = { id: WAZUH_ALERT_ID, timestamp: '2026-11-20T14:41:02.118+0000', rule: { id: '100777', level: 10, description: 'sshd: brute force (contexte)', groups: ['sshd'] }, agent: { id: '003', name: 'srv-web-01', ip: '10.20.1.15' }, full_log: 'Failed password for root from 185.220.101.4' }
  const made = await fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const ref = made.ticket
  check(made.status === 'created' && /^ACME-\d+$/.test(ref), `alerte du scénario ingérée (${ref})`)
  const section = 'section[aria-label="Contexte Wazuh"]'

  // 1. Rien n'est réglé : ni lien ni section sur la fiche
  const m = await login('manager')
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector('.ticket-head')
  check(await m.locator(section).count() === 0 && await m.getByRole('link', { name: /Ouvrir l'alerte dans Wazuh/ }).count() === 0, 'non réglé : ni section « Contexte Wazuh » ni lien vers l\'alerte')

  // 2. L'Admin règle le client ACME
  const a = await login('admin')
  await a.goto(`${BASE}/admin/clients`)
  const block = a.locator('.client-block', { hasText: 'Acme Industrie' })
  await block.getByRole('button', { name: 'Paramétrer' }).click()
  check((await block.locator('h3', { hasText: 'Contexte Wazuh' }).textContent()).includes("désactivé : rien n'est réglé"), 'réglages : fonction annoncée désactivée par défaut')
  const field = (label) => block.getByLabel(label, { exact: false })
  const save = () => block.getByRole('button', { name: 'Enregistrer' }).click()
  await field("Adresse de l'indexeur Wazuh").fill('https://169.254.169.254')
  await save()
  await block.locator('.error[role=alert]').waitFor()
  check((await block.locator('.error[role=alert]').innerText()).includes('lien local'), "réglages : adresse de métadonnées refusée, erreur affichée près du bouton")
  await field("Adresse de l'indexeur Wazuh").fill(idx.url)
  await field("Modèle d'URL de l'alerte").fill('http://wazuh.exemple/?id={alert_id}')
  await save()
  await until(async () => (await block.locator('.error[role=alert]').innerText().catch(() => '')).includes('https://'), 'erreur de modèle')
  check(true, "réglages : modèle d'URL sans HTTPS refusé")
  await field("Modèle d'URL de l'alerte").fill(DASHBOARD)
  await field('Compte en lecture seule : identifiant').fill(idx.user)
  await field('Compte en lecture seule : mot de passe').fill(idx.password)
  await field('Autorité de certification').fill(readFileSync(idx.ca, 'utf8'))
  await save()
  await block.locator('.action-status.ok').waitFor()
  await until(async () => (await block.locator('h3', { hasText: 'Contexte Wazuh' }).textContent()).includes("lecture de l'indexeur active"), 'état actif')
  check(await field('Compte en lecture seule : mot de passe').inputValue() === '' && await field('Compte en lecture seule : identifiant').inputValue() === '', 'réglages : le compte saisi ne reste pas dans le formulaire')
  check((await block.innerText()).includes('Un compte est enregistré (chiffré)') && await block.getByLabel('Effacer le compte enregistré').count() === 1, 'réglages : seul un indicateur « compte enregistré » est montré')
  const listing = await (await a.request.get(`${BASE}/api/v1/admin/clients`)).text()
  check(!listing.includes(idx.password) && !listing.includes(idx.user) && listing.includes('"wazuh_credentials_set":true'), "réglages : l'API ne renvoie jamais le compte de lecture")
  check(!(await a.content()).includes(idx.password), 'réglages : le mot de passe ne figure nulle part dans la page')
  const adminAxe = await axe(a)
  check(adminAxe.length === 0, `accessibilité : éditeur de client avec le contexte Wazuh${adminAxe.length ? ' : ' + JSON.stringify(adminAxe) : ''}`)
  const denied = await a.request.post(`${BASE}/api/v1/tickets/${ref}/wazuh-context`, { data: { before: 5, after: 5 }, headers: { 'X-CSRF-Token': await csrf(a) } })
  check(denied.status() === 403, "l'Admin règle l'accès mais ne peut pas lire le contexte d'un ticket (403)")
  check(a.errors.length === 0, 'aucune erreur JavaScript (admin)')
  await a.context().close()

  // 3. Fiche du ticket pour l'équipe : lien, lecture, conservation
  await m.reload()
  await m.waitForSelector(section)
  const link = m.getByRole('link', { name: /Ouvrir l'alerte dans Wazuh/ })
  const href = await link.getAttribute('href')
  check(href.startsWith('https://wazuh.exemple/') && href.includes(`id:%22${WAZUH_ALERT_ID}%22`) && href.includes("from:'2026-11-20T14%3A36%3A02.118Z'"), "lien vers l'alerte : identifiant et fenêtre de temps de l'alerte d'origine")
  check(await link.getAttribute('target') === '_blank' && await link.getAttribute('rel') === 'noopener noreferrer', "lien vers l'alerte : nouvel onglet, rel=noopener noreferrer")
  check(!(await m.locator(`${section} > details`).evaluate((e) => e.open)), 'section « Contexte Wazuh » repliée par défaut')
  await unfold(m, 'Contexte Wazuh')
  const sec = m.locator(section)
  const before = sec.getByLabel("Événements avant l'alerte")
  check(JSON.stringify(await before.locator('option').allInnerTexts()) === '["5","10","15"]', 'sélecteurs : 5, 10 ou 15 événements')
  await sec.getByLabel("Événements après l'alerte").selectOption('10')
  const fetchBtn = sec.getByRole('button', { name: 'Récupérer' })
  const sizes = await Promise.all([fetchBtn, before].map((l) => l.boundingBox()))
  check(sizes.every((b) => b.height >= 44), 'cibles de 44 px : sélecteurs et bouton Récupérer')
  check(await sec.locator('.wz-list').count() === 0, "aucun événement n'est lu avant la demande")
  await fetchBtn.click()
  await until(async () => await sec.locator('.wz-list li').count() === 16, '5 avant + alerte + 10 après')
  const lines = await sec.locator('.wz-list li').allInnerTexts()
  check(lines[5].includes('Alerte du ticket') && lines[5].includes('Failed password for root') && await sec.locator('.wz-list li.is-alert').count() === 1, "l'alerte du ticket est mise en évidence (libellé et fond) entre les événements avant et après")
  check(lines[0].includes('2026-11-20 14:40:12.118 UTC') && lines[15].includes('2026-11-20 14:42:42.118 UTC'), 'événements horodatés en UTC, du plus ancien au plus récent')
  check(lines.every((l) => !l.includes('SECRET-AUTRE-AGENT') && !l.includes('pc-rh-03')), "aucun événement d'un autre agent")
  check(lines[6].includes('<script>alert(1)</script>') && lines[6].includes('\\x1b') && await sec.locator('.wz-list script').count() === 0, 'journal hostile affiché comme du texte (ni balise, ni caractère de contrôle)')
  check(await sec.locator('.wz-log').first().evaluate((e) => getComputedStyle(e).fontFamily.includes('Mono')), 'journal en chasse fixe')
  check((await sec.locator('.live[role=status]').innerText()).includes('5 événement(s) avant et 10 après'), 'résultat annoncé dans une zone live')
  const ticketNow = await (await m.request.get(`${BASE}/api/v1/tickets/${ref}`)).json()
  check(ticketNow.attachments.length === 0, "afficher le contexte n'enregistre aucune pièce")
  const listAxe = await axe(m)
  check(listAxe.length === 0, `accessibilité : fiche avec le contexte Wazuh affiché${listAxe.length ? ' : ' + JSON.stringify(listAxe) : ''}`)
  const keepBtn = sec.getByRole('button', { name: 'Conserver comme preuve' })
  await keepBtn.click()
  const d = m.locator('dialog[open]')
  await d.waitFor()
  check((await d.locator('h2').innerText()).includes(ref) && (await d.locator('h2').innerText()).includes('15') && /[0-9a-f]{64}/.test(await d.innerText()), 'conservation : le dialogue nomme le ticket, le nombre d\'événements et l\'empreinte SHA-256')
  check((await d.locator('[name=description]').inputValue()).includes('5 événements avant, 10 après'), 'conservation : description proposée, modifiable')
  const dialogAxe = await axe(m)
  check(dialogAxe.length === 0, `accessibilité : dialogue de conservation${dialogAxe.length ? ' : ' + JSON.stringify(dialogAxe) : ''}`)
  await answerDialog(m, { description: 'Contexte SSH autour de l\'alerte (e2e)' })
  await sec.locator('.action-status.ok').waitFor()
  check((await sec.locator('.action-status.ok').innerText()).startsWith('Conservé au registre des preuves à') && await keepBtn.isDisabled(), 'conservation : retour près du bouton, le même jeu ne se conserve pas deux fois')
  await unfold(m, 'Registre des preuves')
  const row = m.locator('section[aria-label="Registre des preuves"] tbody tr', { hasText: 'contexte-wazuh-' })
  await row.waitFor()
  check((await row.innerText()).includes('Extraction indexeur Wazuh') && (await row.innerText()).includes("Contexte SSH autour de l'alerte (e2e)"), 'la pièce figure au registre des preuves (méthode « Extraction indexeur Wazuh »)')
  const kept = (await (await m.request.get(`${BASE}/api/v1/tickets/${ref}`)).json()).attachments
  check(kept.length === 1 && kept[0].visible_client === false && /^[0-9a-f]{64}$/.test(kept[0].sha256) && kept[0].collected_at.endsWith('Z'), 'pièce interne, empreinte SHA-256, date de collecte en UTC')
  // en anglais : la section et le lien sont traduits (les événements, eux, restent tels que Wazuh les a écrits)
  await m.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
  await m.reload()
  await m.waitForSelector('section[aria-label="Wazuh context"]')
  await unfold(m, 'Wazuh context')
  const en = m.locator('section[aria-label="Wazuh context"]')
  await en.getByRole('button', { name: 'Fetch' }).click()
  await until(async () => await en.locator('.wz-list li').count() === 11, 'liste en anglais')
  const labels = await en.evaluate((e) => { const c = e.cloneNode(true); c.querySelectorAll('.wz-log, .wz-meta > span:last-child').forEach((x) => x.remove()); return c.innerText })
  check(!/[àâçéèêëîïôûùüœÀÂÇÉÈÊËÎÏÔÛÙÜŒ]/.test(labels) && labels.includes('Events before the alert') && labels.includes('Ticket alert') && labels.includes('Keep as evidence'), `traduction anglaise de la section « Contexte Wazuh »${/[àâçéèêëîïôûùüœ]/i.test(labels) ? ' — reste : ' + labels.split('\n').filter((l) => /[àâçéèêëîïôûùüœ]/i.test(l)).slice(0, 3).join(' | ') : ''}`)
  check(await m.getByRole('link', { name: /Open the alert in Wazuh/ }).count() === 1, 'traduction anglaise du lien vers l\'alerte')
  await m.evaluate(() => localStorage.setItem('keryx_lang', 'fr'))
  await m.reload()
  await m.waitForSelector(section)
  await unfold(m, 'Contexte Wazuh')
  // indexeur arrêté : erreur claire, près de la commande
  stack.indexer.stop()
  await new Promise((r) => setTimeout(r, 500))
  await fetchBtn.click()
  await sec.locator('.error[role=alert]').waitFor()
  check((await sec.locator('.error[role=alert]').innerText()).includes('injoignable') && await sec.locator('.wz-list').count() === 0, 'indexeur injoignable : message clair (role=alert), aucun résultat périmé affiché')
  check(m.errors.length === 0, 'aucune erreur JavaScript (manager)')
  await m.context().close()

  // 4. Le client : ni lien, ni section, ni pièce, ni accès à la lecture
  const c = await login('client')
  await c.goto(`${BASE}/tickets/${ref}`)
  await c.waitForSelector('.ticket-head')
  check(await c.locator(section).count() === 0 && await c.locator('a[href*="wazuh.exemple"]').count() === 0, 'client : ni section « Contexte Wazuh » ni lien vers Wazuh')
  const seen = await (await c.request.get(`${BASE}/api/v1/tickets/${ref}`)).text()
  check(!('wazuh' in JSON.parse(seen)) && !seen.includes('wazuh.exemple') && !seen.includes('contexte-wazuh-') && JSON.parse(seen).attachments.length === 0, "client : la réponse de l'API ne contient ni le lien ni la pièce conservée")
  const refused = await c.request.post(`${BASE}/api/v1/tickets/${ref}/wazuh-context`, { data: { before: 5, after: 5 }, headers: { 'X-CSRF-Token': await csrf(c) } })
  check(refused.status() === 403, 'client : lecture du contexte refusée (403)')
  check(c.errors.length === 0, 'aucune erreur JavaScript (client)')
  await c.context().close()
}
