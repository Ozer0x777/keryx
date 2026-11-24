// File de triage : l'état des filtres fait l'aller-retour par l'URL sans perte, et une URL abîmée ne casse pas la liste.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { cardActive, cardPatch, DEFAULTS, filtersFromSearch, filtersToSearch, OPEN_STATUSES } from '../src/queue.js'

test('sans paramètre : filtres par défaut, URL vide', () => {
  assert.deepEqual(filtersFromSearch(''), DEFAULTS)
  assert.deepEqual(filtersToSearch(DEFAULTS), {})
})

test("aller-retour : filtres, tri et vue sont restaurés depuis l'URL", () => {
  const f = { ...DEFAULTS, status: OPEN_STATUSES, severity: 'Critique', q: 'ssh échec', assignee: 'me', overdue: true, sort: 'gravite', order: 'asc' }
  const qs = new URLSearchParams(filtersToSearch(f)).toString()
  assert.deepEqual(filtersFromSearch(`?${qs}`), f)
  assert.ok(!qs.includes('rex_en_attente') && !qs.includes('client'))   // les valeurs par défaut ne figurent pas dans l'URL
})

test('valeurs inconnues : retour aux défauts (pas de tri ni de gravité que le serveur refuserait)', () => {
  const f = filtersFromSearch('?sort=nimporte&order=haut&severity=Grave&overdue=oui&inconnu=1')
  assert.equal(f.sort, 'created'); assert.equal(f.order, 'desc'); assert.equal(f.severity, ''); assert.equal(f.overdue, false)
  assert.ok(!('inconnu' in f))
})

test('cartes-filtres : une carte est enfoncée quand ses critères d’état sont exactement appliqués', () => {
  const critiques = { status: OPEN_STATUSES, severity: 'Critique' }
  const f = { ...DEFAULTS, q: 'srv', assignee: 'me', ...cardPatch(critiques) }
  assert.ok(cardActive(f, critiques))
  assert.equal(f.q, 'srv'); assert.equal(f.assignee, 'me')              // recherche et vue conservées
  assert.ok(!cardActive({ ...f, overdue: true }, critiques))              // un critère d'état en plus : ce n'est plus cette carte
  assert.ok(!cardActive(f, { overdue: true }))
  assert.deepEqual(cardPatch({ overdue: true }), { status: '', severity: '', overdue: true, rex_en_attente: false, awaiting_client: false, incomplete: false })
})

test('vues de priorisation : elles fixent leurs propres critères, y compris l\'assigné, et se désactivent entre elles', () => {
  const critiquesLibres = { status: OPEN_STATUSES, severity: 'Critique', assignee: 'none' }
  const attenteClient = { awaiting_client: true, assignee: '' }
  const f = { ...DEFAULTS, q: 'srv', ...cardPatch(critiquesLibres) }
  assert.ok(cardActive(f, critiquesLibres) && f.assignee === 'none' && f.q === 'srv')
  const g = { ...f, ...cardPatch(attenteClient) }
  assert.ok(cardActive(g, attenteClient) && !cardActive(g, critiquesLibres))
  assert.equal(g.assignee, '')                      // plus d'assigné caché de la vue précédente
  assert.equal(g.severity, '')                      // ni de gravité
  const qs = new URLSearchParams(filtersToSearch(g)).toString()
  assert.deepEqual(filtersFromSearch(`?${qs}`), g)  // l'URL restitue la vue
})
