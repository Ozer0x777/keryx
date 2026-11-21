// Non-régression : la date de début par défaut des rapports est le 1er du mois (UTC), quel que soit le fuseau du poste.
// Lancer avec : npm test (node --test).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isoDay, isoToUtcInput, monthStartUtc, untilUtc, utcClock, utcInputNow, utcInputToIso } from '../src/dates.js'

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

// Champs datetime-local : la saisie est en UTC (comme tous les affichages), quel que soit le fuseau du poste.
for (const tz of ZONES) {
  test(`saisie de date et heure en UTC, poste réglé sur ${tz}`, () => {
    process.env.TZ = tz
    const now = new Date('2026-11-21T23:30:45Z')
    assert.equal(utcInputNow(now), '2026-11-21T23:30')                       // valeur par défaut du champ = heure UTC
    assert.equal(utcInputToIso('2026-11-21T23:30'), '2026-11-21T23:30:00.000Z')
    assert.equal(isoToUtcInput('2026-11-21T23:30:00+00:00'), '2026-11-21T23:30')
    assert.equal(isoToUtcInput(utcInputToIso('2026-03-29T02:30')), '2026-03-29T02:30')   // heure « inexistante » à Paris (changement d'heure)
    assert.equal(utcInputToIso(''), null); assert.equal(isoToUtcInput(null), '')
    assert.equal(utcClock(now), '23:30 UTC')
  })
}

test("l'ancienne saisie en heure locale décalait l'heure affichée ensuite en UTC", () => {
  process.env.TZ = 'Europe/Paris'
  assert.equal(new Date('2026-11-21T14:00').toISOString(), '2026-11-21T13:00:00.000Z')   // le défaut corrigé : 14:00 saisi, 13:00 UTC affiché
  assert.equal(utcInputToIso('2026-11-21T14:00'), '2026-11-21T14:00:00.000Z')
})

test('temps restant avant une échéance, ou écoulé depuis', () => {
  const now = Date.parse('2026-11-21T12:00:00Z')
  assert.deepEqual(untilUtc('2026-11-21T14:05:00Z', now), { late: false, days: 0, hours: 2, minutes: 5 })
  assert.deepEqual(untilUtc('2026-11-21T11:25:00Z', now), { late: true, days: 0, hours: 0, minutes: 35 })
  assert.deepEqual(untilUtc('2026-11-24T16:00:00Z', now), { late: false, days: 3, hours: 4, minutes: 0 })
})
