// Recherche d'empreinte sur VirusTotal (ADR-0022) : clé saisie au profil, recherche depuis une pièce, depuis une alerte
// et en saisie manuelle, fichier inconnu jamais présenté comme sain, et rien de tout cela pour le client ni pour l'Admin.
// VirusTotal est le faux serveur local (tests/fake_virustotal.py) : ce parcours n'envoie rien au vrai service et ne
// prouve pas la compatibilité avec lui.
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { answerDialog, unfold, until } from '../harness.mjs'
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')

const axe = async (page) => {
  await page.evaluate(axeSource)  // eslint-disable-line
  await page.evaluate(() => Promise.all(document.getAnimations().filter((a) => a.effect?.getComputedTiming().endTime !== Infinity).map((a) => a.finished.catch(() => {}))))   // fondu d'un dialogue terminé : contraste mesuré sur l'état final
  return page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } })).violations
    .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0].target.join(' '), help: v.help })))
}
const csrf = async (page) => (await page.context().cookies()).find((c) => c.name === 'keryx_csrf').value
const EMPTY_ZIP = Buffer.from('504b0506000000000000000000000000000000000000', 'hex')
const PIECE_SHA256 = createHash('sha256').update(EMPTY_ZIP).digest('hex')

export default async ({ stack, BASE, check, login }) => {
  const vt = await stack.virustotal.ready          // { key, eicar, piece, quiet, unknown } : ce que connaît le faux serveur
  check(vt.piece === PIECE_SHA256, 'le faux VirusTotal connaît l\'empreinte de la pièce du parcours')
  const sha1 = '3395856ce81f2b7382dee72602f798b642f14140'
  const alert = { id: 'e2e-vt-1', timestamp: '2026-11-20T16:00:00.000+0000', rule: { id: '100796', level: 9, description: 'File added to the system (e2e 96)', groups: ['syscheck'] }, agent: { id: '003', name: 'srv-web-01' },
    syscheck: { path: '/tmp/charge.bin', event: 'added', md5_after: 'd'.repeat(32), sha1_after: sha1, sha256_after: vt.eicar } }
  const made = await fetch(`${BASE}/api/v1/ingest/wazuh`, { method: 'POST', headers: { Authorization: `Bearer ${stack.seeds.apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(alert) }).then((r) => r.json())
  const ref = made.ticket
  check(made.status === 'created' && /^ACME-\d+$/.test(ref), `alerte du scénario ingérée (${ref})`)
  const section = 'section[aria-label="VirusTotal"]'
  const proofs = 'section[aria-label="Registre des preuves"]'

  // 1. Sans clé : la fonction est là (disponible par défaut), mais elle renvoie au profil et rien ne part
  const m = await login('manager')
  // Accord du client à la recherche d'empreintes chez VirusTotal (PDIS IV.1.g), refusée par défaut
  const csrf = (await m.context().cookies()).find((c) => c.name === 'keryx_csrf').value
  const accord = await m.request.put(`${BASE}/api/v1/politique/ACME`, { data: { virustotal_autorise: true }, headers: { 'X-CSRF-Token': csrf } })
  check(accord.ok() && (await accord.json()).virustotal_autorise === true, 'accord du client enregistré par le manager')
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector(section, { state: 'attached' })
  check(!(await m.locator(`${section} > details`).evaluate((e) => e.open)), 'panneau « VirusTotal » présent et replié par défaut')
  await unfold(m, 'Registre des preuves')
  writeFileSync('/tmp/e2e-vt-piece.zip', EMPTY_ZIP)
  await m.getByRole('button', { name: /Déposer un fichier/ }).click()
  await m.setInputFiles('input[type=file][name=file]', '/tmp/e2e-vt-piece.zip')
  await m.fill('input[name=description]', 'Charge suspecte'); await m.fill('input[name=method]', 'copie depuis le poste')
  await m.getByRole('button', { name: 'Déposer', exact: true }).click()
  const row = m.locator(`${proofs} tbody tr`, { hasText: 'e2e-vt-piece.zip' })
  await row.waitFor()
  const pieceBtn = row.getByRole('button', { name: /Chercher l'empreinte de « e2e-vt-piece.zip » sur VirusTotal/ })
  await pieceBtn.click()
  await row.locator('.error[role=alert]').waitFor()
  check((await row.locator('.error[role=alert]').innerText()).includes("Aucune clé d'API VirusTotal") && await row.locator('.error[role=alert] a[href="/profil"]').count() === 1, 'sans clé : le bouton d\'une pièce renvoie au profil (role=alert, lien)')
  await unfold(m, 'VirusTotal')
  const sec = m.locator(section)
  check((await sec.innerText()).includes("Seule l'empreinte est envoyée, jamais le fichier.") && await sec.locator('a[href="/profil"]').count() === 1 && await sec.locator('input').count() === 0, 'sans clé : le panneau l\'explique, renvoie au profil et ne propose aucune recherche')
  const before = (await (await m.request.get(`${BASE}/api/v1/tickets/${ref}`)).json()).virustotal
  check(before.lookups.length === 0, 'sans clé : aucune recherche enregistrée')

  // 2. Profil : saisir la clé
  await sec.locator('a[href="/profil"]').click()
  const key = m.locator('section[aria-label="VirusTotal"]')
  await key.locator('[data-testid=vt-key-state]').waitFor()
  check((await key.locator('[data-testid=vt-key-state]').innerText()).startsWith('Aucune clé enregistrée'), 'profil : état « aucune clé enregistrée »')
  check((await key.innerText()).includes("Seule l'empreinte est envoyée, jamais le fichier."), 'profil : phrase « seule l\'empreinte est envoyée, jamais le fichier »')
  const input = key.getByLabel("Clé d'API VirusTotal")
  check(await input.getAttribute('type') === 'password' && await input.getAttribute('autocomplete') === 'off', 'profil : champ de type mot de passe, sans saisie automatique')
  const saveBtn = key.getByRole('button', { name: 'Enregistrer la clé' })
  const sizes = await Promise.all([input, saveBtn].map((l) => l.boundingBox()))
  check(sizes.every((b) => b.height >= 44), 'profil : champ et bouton de 44 px')
  await input.fill('cle-avec-des-tirets-et-donc-refusee-par-keryx')
  await saveBtn.click()
  await key.locator('.error[role=alert]').waitFor()
  check((await key.locator('.error[role=alert]').innerText()).includes('lettres et chiffres') && !(await key.locator('.error[role=alert]').innerText()).includes('tirets'), 'profil : clé de forme invalide refusée près du bouton, sans être recopiée')
  await input.fill(vt.key)
  await saveBtn.click()
  await key.locator('.action-status.ok').waitFor()
  await until(async () => (await key.locator('[data-testid=vt-key-state]').innerText()).startsWith('Une clé est enregistrée (chiffrée)'), 'état « enregistrée »')
  check((await key.locator('.action-status.ok').innerText()) === 'Clé enregistrée.' && await key.locator('.action-status.ok').getAttribute('role') === 'status', 'profil : clé enregistrée, retour près du bouton (role=status)')
  check(await key.getByLabel("Nouvelle clé d'API VirusTotal").inputValue() === '' && !(await m.content()).includes(vt.key), 'profil : la clé ne reste ni dans le champ ni dans la page')
  const state = await (await m.request.get(`${BASE}/api/v1/me/virustotal`)).text()
  check(state === '{"configured":true,"enabled":true}', "profil : l'API ne renvoie que l'état, jamais la clé")
  check(await key.getByRole('button', { name: 'Remplacer la clé' }).count() === 1 && await key.getByRole('button', { name: 'Retirer la clé' }).count() === 1, 'profil : remplacer ou retirer la clé')
  const profileAxe = await axe(m)
  check(profileAxe.length === 0, `accessibilité : profil avec la section VirusTotal${profileAxe.length ? ' : ' + JSON.stringify(profileAxe) : ''}`)

  // 3. Fiche : recherche depuis la pièce (le serveur prend l'empreinte lui-même)
  await m.goto(`${BASE}/tickets/${ref}`)
  await m.waitForSelector(section, { state: 'attached' })
  await unfold(m, 'Registre des preuves')
  await row.waitFor()
  const box = await pieceBtn.boundingBox()
  const hit = await pieceBtn.evaluate((e) => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e, '::after'); return r.height - parseFloat(s.top) - parseFloat(s.bottom) })
  check(box.height >= 30 && hit >= 44, `bouton d'une pièce : zone cliquable de 44 px (${Math.round(hit)} px)`)
  await pieceBtn.click()
  await row.locator('[data-vt=malveillant]').waitFor()
  check((await row.locator('[data-vt=malveillant]').innerText()) === 'Malveillant : 12 / 73' && await row.locator('[data-vt=malveillant]').evaluate((e) => e.classList.contains('danger')), 'pièce : résultat dans la ligne (libellé et couleur)')
  check((await m.locator('p[role=status].sr-only').innerText()).includes('12 moteur(s) sur 73'), 'pièce : résultat annoncé dans la zone live de la fiche')
  let t = await (await m.request.get(`${BASE}/api/v1/tickets/${ref}`)).json()
  const piece = t.attachments.find((a) => a.filename === 'e2e-vt-piece.zip')
  check(t.virustotal.lookups.length === 1 && t.virustotal.lookups[0].hash === PIECE_SHA256 && t.virustotal.lookups[0].source_type === 'piece' && t.virustotal.lookups[0].source_id === piece.id && t.virustotal.lookups[0].created_at.endsWith('Z'), "pièce : recherche enregistrée avec l'empreinte prise par le serveur, date en UTC")
  const custody = await (await m.request.get(`${BASE}/api/v1/attachments/${piece.id}/custody`)).json()
  check(custody.items.map((c) => c.action).join() === 'depot,analyse_virustotal', 'pièce : événement « analyse_virustotal » dans la chaîne de possession')
  check(t.events.some((e) => e.action === 'virustotal_lookup' && e.details.empreinte === PIECE_SHA256), 'recherche inscrite au registre des actions du ticket')

  // 4. Panneau : saisie manuelle, alertes, fichier inconnu
  await unfold(m, 'VirusTotal')
  const field = sec.getByLabel('Empreinte SHA-256 ou SHA-1')
  const go = sec.getByRole('button', { name: 'Chercher sur VirusTotal' })
  await sec.locator('.vt-cands li').first().waitFor()
  const cands = await sec.locator('.vt-cands li').allInnerTexts()
  check(cands.length === 2 && cands[0].includes(sha1) && cands[0].includes('syscheck.sha1_after') && cands[1].includes(vt.eicar) && cands[1].includes('/tmp/charge.bin') && !cands.join().includes('d'.repeat(32)), 'empreintes des alertes : SHA-1 et SHA-256 du contrôle d\'intégrité, pas le MD5')
  const targets = await Promise.all([field, go, sec.locator('.vt-cands button').first(), sec.locator('.vt-list summary').first()].map((l) => l.boundingBox()))
  check(targets.every((b) => b.height >= 44), `cibles de 44 px : champ, bouton, « Chercher » d'une alerte, détail d'un résultat (${targets.map((b) => Math.round(b.height)).join(', ')})`)
  await field.fill('d'.repeat(32))
  await go.click()
  await sec.locator('.field-error[role=alert]').waitFor()
  check((await sec.locator('.field-error').innerText()).includes("MD5 n'est pas accepté") && await field.getAttribute('aria-invalid') === 'true', 'saisie : un MD5 est refusé avant tout envoi (role=alert, champ marqué invalide)')
  await field.fill(`  ${vt.eicar.toUpperCase()} `)
  await go.click()
  await until(async () => (await sec.locator('.live[role=status]').innerText()).includes('62 moteur(s) sur 73'), 'résultat EICAR')
  check(true, 'saisie manuelle : résultat annoncé dans la zone live du panneau (role=status)')
  const first = sec.locator('.vt-list > li').first()
  check(await first.locator('details').evaluate((e) => e.open), 'le détail de la recherche qui vient d\'aboutir est déplié')
  const detail = await first.innerText()
  check(detail.includes('Saisie manuelle') && detail.includes('par manager') && detail.includes(vt.eicar) && detail.includes('eicar.com') && detail.includes('trojan.eicar/test') && detail.includes('2026-11-14 10:00 UTC') && detail.includes('Moteur00'), 'détail : source, auteur, empreinte, nom, étiquette, dernière analyse en UTC, noms des moteurs')
  const link = first.getByRole('link', { name: /Ouvrir la fiche sur VirusTotal/ })
  check(await link.getAttribute('href') === `https://www.virustotal.com/gui/file/${vt.eicar}` && await link.getAttribute('target') === '_blank' && await link.getAttribute('rel') === 'noopener noreferrer', 'lien vers VirusTotal construit par Keryx : nouvel onglet, rel=noopener noreferrer')
  // fichier inconnu : jamais « sain »
  await field.fill(vt.unknown)
  await go.click()
  await until(async () => (await sec.locator('.live[role=status]').innerText()).startsWith('Inconnu de VirusTotal'), 'résultat inconnu')
  const unknown = sec.locator('.vt-list > li').first()
  const pill = unknown.locator('[data-vt=inconnu]')
  const pillStyle = await pill.evaluate((e) => ({ cls: e.className, bg: getComputedStyle(e).backgroundColor }))
  check((await pill.innerText()) === 'Inconnu de VirusTotal' && pillStyle.cls === 'pill' && pillStyle.bg === 'rgb(238, 240, 243)', `inconnu : libellé et couleur neutres (${pillStyle.bg})`)
  check((await unknown.innerText()).includes("Cela ne dit rien du fichier, ni qu'il est dangereux, ni qu'il est sans danger."), 'inconnu : phrase explicite')
  check(!/\bsain\b|\bsaine\b|\bclean\b/i.test(await sec.innerText()) && await sec.locator('.pill.ok').count() === 0, 'panneau : aucun résultat n\'est présenté comme sain, aucune pastille verte')
  // depuis une alerte
  await sec.locator('.vt-cands button').first().click()
  await until(async () => (await sec.locator('.vt-list > li').first().innerText()).includes('Alerte Wazuh'), 'recherche depuis une alerte')
  check((await sec.locator('.vt-list > li').first().innerText()).includes(`SHA-1 ${sha1}`) && (await sec.locator('.vt-cands li').first().innerText()).includes('Malveillant : 62 / 73'), 'alerte : recherche par SHA-1, résultat rappelé près de l\'empreinte')
  t = await (await m.request.get(`${BASE}/api/v1/tickets/${ref}`)).json()
  check(t.virustotal.lookups.map((l) => `${l.source_type}:${l.status}`).join() === 'alerte:trouve,saisie:inconnu,saisie:trouve,piece:trouve', 'quatre recherches enregistrées (pièce, saisie connue, saisie inconnue, alerte)')
  check((await sec.locator('.fold-summary').innerText()) === '4 recherche(s)', 'en-tête du panneau : nombre de recherches')
  const panelAxe = await axe(m)
  check(panelAxe.length === 0, `accessibilité : fiche avec le panneau VirusTotal et ses résultats${panelAxe.length ? ' : ' + JSON.stringify(panelAxe) : ''}`)
  // écran étroit : le registre des preuves défile dans son cadre, la fiche ne déborde pas
  await m.setViewportSize({ width: 390, height: 800 })
  await m.waitForTimeout(400)
  const over = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  check(over <= 1, `à 390 px : aucun débordement horizontal de la fiche avec une pièce et des résultats (${over} px)`)
  await m.setViewportSize({ width: 1400, height: 900 })
  // en anglais
  await m.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
  await m.reload()
  await m.waitForSelector(section, { state: 'attached' })
  await unfold(m, 'VirusTotal')
  await sec.locator('.vt-cands li').first().waitFor()
  const labels = await sec.evaluate((e) => { const c = e.cloneNode(true); c.querySelectorAll('.vt-hash, .vt-detail dd, .vt-meta > span:last-child').forEach((x) => x.remove()); return c.innerText })
  check(!/[àâçéèêëîïôûùüœÀÂÇÉÈÊËÎÏÔÛÙÜŒ]/.test(labels) && labels.includes('Only the hash is sent, never the file.') && labels.includes('Unknown to VirusTotal') && labels.includes('Look up on VirusTotal') && labels.includes('Manual entry'), `traduction anglaise du panneau « VirusTotal »${/[àâçéèêëîïôûùüœ]/i.test(labels) ? ' — reste : ' + labels.split('\n').filter((l) => /[àâçéèêëîïôûùüœ]/i.test(l)).slice(0, 3).join(' | ') : ''}`)
  await m.evaluate(() => localStorage.setItem('keryx_lang', 'fr'))
  await m.reload()
  await m.waitForSelector(section, { state: 'attached' })
  await unfold(m, 'VirusTotal')

  // 5. Le client et l'Admin : rien
  const c = await login('client')
  await c.goto(`${BASE}/tickets/${ref}`)
  await c.waitForSelector('.ticket-head')
  check(await c.locator(section).count() === 0 && await c.getByRole('button', { name: /VirusTotal/ }).count() === 0, 'client : ni panneau ni bouton « VirusTotal »')
  const seen = await (await c.request.get(`${BASE}/api/v1/tickets/${ref}`)).text()
  check(!('virustotal' in JSON.parse(seen)) && !/virustotal/i.test(seen) && !seen.includes(vt.eicar), "client : la réponse de l'API ne contient aucune trace des recherches")
  const refused = await c.request.post(`${BASE}/api/v1/tickets/${ref}/virustotal`, { data: { source: 'saisie', hash: vt.eicar }, headers: { 'X-CSRF-Token': await csrf(c) } })
  check(refused.status() === 403 && (await c.request.get(`${BASE}/api/v1/me/virustotal`)).status() === 403, 'client : recherche et clé refusées (403)')
  await c.goto(`${BASE}/profil`)
  await c.waitForSelector('text=Sessions actives')
  check(await c.locator(section).count() === 0 && !/virustotal/i.test(await c.locator('main, .content').first().innerText()), 'client : aucune section VirusTotal dans le profil')
  check(c.errors.length === 0, 'aucune erreur JavaScript (client)')
  await c.context().close()
  const a = await login('admin')
  await a.goto(`${BASE}/profil`)
  await a.waitForSelector('text=Sessions actives')
  check(await a.locator(section).count() === 0, 'admin : aucune section VirusTotal dans le profil')
  const denied = await a.request.post(`${BASE}/api/v1/tickets/${ref}/virustotal`, { data: { source: 'saisie', hash: vt.eicar }, headers: { 'X-CSRF-Token': await csrf(a) } })
  const users = await (await a.request.get(`${BASE}/api/v1/admin/users`)).text()
  check(denied.status() === 403 && (await a.request.get(`${BASE}/api/v1/me/virustotal`)).status() === 403 && !users.includes(vt.key) && !/vt_api_key|virustotal/i.test(users), "admin : aucune recherche, aucune clé, et rien de la clé des autres dans la liste des comptes")
  check(a.errors.length === 0, 'aucune erreur JavaScript (admin)')
  await a.context().close()

  // 6. VirusTotal injoignable : erreur claire près de la commande, rien d'enregistré ; puis retrait de la clé
  stack.virustotal.stop()
  await new Promise((r) => setTimeout(r, 500))
  await field.fill(vt.quiet)
  await go.click()
  await sec.locator('.error[role=alert]').waitFor()
  check((await sec.locator('.error[role=alert]').innerText()).includes('injoignable'), 'VirusTotal injoignable : message clair (role=alert)')
  t = await (await m.request.get(`${BASE}/api/v1/tickets/${ref}`)).json()
  check(t.virustotal.lookups.length === 4, 'un échec n\'enregistre aucun résultat')
  await m.goto(`${BASE}/profil`)
  await key.getByRole('button', { name: 'Retirer la clé' }).click()
  const d = m.locator('dialog[open]')
  await d.waitFor()
  check((await d.locator('h2').innerText()) === 'Retirer votre clé VirusTotal ?', 'retrait de la clé : dialogue de confirmation')
  await answerDialog(m)
  await until(async () => (await key.locator('[data-testid=vt-key-state]').innerText()).startsWith('Aucune clé enregistrée'), 'clé retirée')
  check((await (await m.request.get(`${BASE}/api/v1/me/virustotal`)).text()) === '{"configured":false,"enabled":true}', 'clé retirée : état « non enregistrée »')
  check(m.errors.length === 0, 'aucune erreur JavaScript (manager)')
  await m.context().close()
}
