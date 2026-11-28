// Contrôle large : tout texte à accents ou mot-outil français restant en mode anglais est signalé (hors données saisies).
import { unfoldAll } from '../harness.mjs'

const FR = /[àâçéèêëîïôûùüÿœÀÂÇÉÈÊËÎÏÔÛÙÜŒ]|\b(le|la|les|des|du|une|pour|avec|dans|est|sur|vos|votre|aucun|aucune|cette|ces|nous|sans)\b/
const IGNORE = /^(?:\d+\t.*|[a-zé_]+ — .*|Réinitialiser les mots de passe.*|Règle\t.*|Décodeur|Description\t.*|Emplacement|Horodatage Wazuh.*|Identifiant d'alerte.*|Français|Accusé|.*(?:Test (?:manager|analyste|admin|client)|Acme Industrie|Transports Delta|Nova SA|nouvel\.analyste|Nouvel Analyste|Journal exporté|export manuel|MITRE ATT&CK|Brute Force|Wazuh|srv-)).*$/
export default async ({ BASE, check, login }) => {
  const scanAll = async (p, paths, label) => {
    await p.evaluate(() => localStorage.setItem('keryx_lang', 'en'))
    const leaks = []
    for (const path of paths) {
      await p.goto(`${BASE}${path}`); await p.waitForTimeout(1100)
      await unfoldAll(p)   // les panneaux repliés de la fiche ticket comptent aussi
      // Données enregistrées (valeurs du journal d'audit, etc.) marquées translate="no" : hors contrôle.
      const text = await p.locator('main, .content').first().evaluate((el) => {
        const hidden = [...el.querySelectorAll('[translate="no"]')]
        hidden.forEach((n) => { n.dataset.e2eDisplay = n.style.display; n.style.display = 'none' })
        const t = el.innerText
        hidden.forEach((n) => { n.style.display = n.dataset.e2eDisplay; delete n.dataset.e2eDisplay })
        return t
      })
      const lines = text.split('\n').map((l) => l.trim()).filter(Boolean)
      for (const l of lines) if (FR.test(l) && !IGNORE.test(l)) leaks.push(`${path} : ${l.slice(0, 90)}`)
    }
    try { (await import('node:fs')).appendFileSync('/tmp/leaks.txt', [...new Set(leaks)].join('\n') + '\n') } catch {}
    check(leaks.length === 0, `aucun texte français restant (${label})${leaks.length ? ' — ' + [...new Set(leaks)].slice(0, 6).join(' ;; ') : ''}`)
  }
  const m = await login('manager')
  await scanAll(m, ['/tickets', '/kanban', '/parc?client=ACME', '/pilotage', '/rapports', '/tickets/ACME-1', '/tickets/ACME-1/rapport', '/mitre', '/audit', '/profil'], 'manager')
  await m.context().close()
  const a = await login('admin')
  await scanAll(a, ['/admin/comptes', '/admin/clients', '/admin/cles', '/admin/mitre', '/admin/revue', '/admin/audit', '/admin/systeme'], 'admin')
  await a.context().close()
  const c = await login('client')
  await scanAll(c, ['/tickets', '/parc', '/tickets/ACME-1'], 'client')
  await c.context().close()
}
