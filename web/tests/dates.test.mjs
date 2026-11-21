// Non-régression : la date de début par défaut des rapports est le 1er du mois (UTC), quel que soit le fuseau du poste.
// Lancer avec : npm test (node --test).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isoDay, monthStartUtc } from '../src/dates.js'

const ZONES = ['UTC', 'Europe/Paris', 'Pacific/Kiritimati', 'America/Los_Angeles', 'Asia/Kolkata']

for (const tz of ZONES) {
  test(`début de mois en UTC, poste réglé sur ${tz}`, () => {
    process.env.TZ = tz
    assert.equal(monthStartUtc(new Date('2026-11-21T10:00:00Z')), '2026-11-01')
    assert.equal(monthStartUtc(new Date('2026-11-01T00:00:00Z')), '2026-11-01')   // minuit UTC pile
    assert.equal(monthStartUtc(new Date('2026-10-31T23:59:59Z')), '2026-10-01')   // déjà novembre à l'est, encore octobre en UTC
    assert.equal(monthStartUtc(new Date('2027-01-01T00:30:00Z')), '2027-01-01')   // changement d'année
    assert.equal(isoDay(new Date('2026-11-21T23:30:00Z')), '2026-11-21')
  })
}

test("l'ancienne construction en heure locale était fausse à l'est de Greenwich", () => {
  process.env.TZ = 'Europe/Paris'
  const now = new Date('2026-11-21T10:00:00Z')
  const local = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10)
  assert.equal(local, '2026-10-31')            // le défaut corrigé
  assert.equal(monthStartUtc(now), '2026-11-01')
})
