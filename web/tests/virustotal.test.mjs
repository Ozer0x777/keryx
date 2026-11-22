// Recherche VirusTotal : un fichier inconnu ou sans détection n'est jamais présenté comme sain ; seule une vraie
// empreinte est acceptée ; seul le lien construit par Keryx devient un lien.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isHash, lastFor, normalizeHash, shortHash, verdict, vtLink } from '../src/virustotal.js'

const SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
const SHA1 = '3395856ce81f2b7382dee72602f798b642f14140'
const found = (stats) => ({ status: 'trouve', hash: SHA256, summary: { stats } })

test('empreinte : SHA-256 ou SHA-1 en minuscules, rien d’autre', () => {
  assert.ok(isHash(SHA256) && isHash(SHA1))
  for (const bad of ['d'.repeat(32), 'A'.repeat(64), 'g'.repeat(64), `${SHA256} `, `${SHA1}/..`, '', null, undefined, 5, [SHA256]]) assert.equal(isHash(bad), false)
  assert.equal(normalizeHash(`  ${SHA256.toUpperCase()}\n`), SHA256)
  assert.equal(shortHash(SHA256), '275a021bbfb6…51fd0f')
  assert.equal(shortHash('<script>'), '')
})

test('résultat : jamais de ton « ok », ni pour un inconnu ni pour une absence de détection', () => {
  const cases = [
    [{ status: 'inconnu', hash: SHA256, summary: {} }, 'inconnu', ''],
    [found({ malicious: 0, suspicious: 0, harmless: 70, undetected: 3, total: 73 }), 'aucune_detection', ''],
    [found({ malicious: 62, suspicious: 1, total: 73 }), 'malveillant', 'danger'],
    [found({ malicious: 0, suspicious: 2, total: 73 }), 'suspect', 'warn'],
    [found({}), 'aucune_detection', ''],
    [{ status: 'sain', summary: { stats: { malicious: 0 } } }, 'inconnu', ''],       // statut inattendu : pas « trouvé », donc neutre
    [null, 'inconnu', ''],
  ]
  for (const [lookup, kind, tone] of cases) {
    const v = verdict(lookup)
    assert.equal(v.kind, kind); assert.equal(v.tone, tone); assert.notEqual(v.tone, 'ok')
  }
})

test('résultat : compteurs douteux ramenés à zéro, total jamais inférieur aux détections', () => {
  assert.deepEqual(verdict(found({ malicious: '62', suspicious: -1, total: NaN })), { kind: 'aucune_detection', tone: '', malicious: 0, suspicious: 0, total: 0 })
  assert.equal(verdict(found({ malicious: 5, suspicious: 2, total: 1 })).total, 7)
})

test('lien : seulement celui que Keryx construit pour cette empreinte', () => {
  const ok = `https://www.virustotal.com/gui/file/${SHA256}`
  assert.equal(vtLink({ hash: SHA256, url: ok }), ok)
  for (const url of [`https://attaquant.example/gui/file/${SHA256}`, `javascript:alert(1)//${SHA256}`, `${ok}?x=1`, `https://www.virustotal.com/gui/file/${SHA1}`, undefined]) {
    assert.equal(vtLink({ hash: SHA256, url }), null)
  }
  assert.equal(vtLink({ hash: 'pas-une-empreinte', url: 'https://www.virustotal.com/gui/file/pas-une-empreinte' }), null)
})

test('dernière recherche d’une pièce', () => {
  const lookups = [{ id: 2, source_id: 'a' }, { id: 1, source_id: 'a' }, { id: 0, source_id: 'b' }]
  assert.equal(lastFor(lookups, (l) => l.source_id === 'a').id, 2)
  assert.equal(lastFor(lookups, (l) => l.source_id === 'z'), null)
  assert.equal(lastFor(undefined, () => true), null)
})
