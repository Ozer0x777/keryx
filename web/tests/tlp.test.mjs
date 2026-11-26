// TLP plancher d'un client (ADR-0033) : ordre du marquage et niveau proposé pour une pièce.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { tlpAuMoins, tlpRang, tlpSous } from '../src/tlp.js'

test('ordre : CLEAR < GREEN < AMBER < AMBER+STRICT < RED', () => {
  assert.ok(tlpRang('TLP:CLEAR') < tlpRang('TLP:GREEN') && tlpRang('TLP:AMBER+STRICT') < tlpRang('TLP:RED'))
})

test('sous le plancher, et aucun plancher', () => {
  assert.equal(tlpSous('TLP:GREEN', 'TLP:AMBER'), true)
  assert.equal(tlpSous('TLP:AMBER', 'TLP:AMBER'), false)
  assert.equal(tlpSous('TLP:RED', 'TLP:AMBER'), false)
  assert.equal(tlpSous('TLP:CLEAR', null), false)
})

test('pièce : au moins le plancher', () => {
  assert.equal(tlpAuMoins('TLP:GREEN', 'TLP:AMBER+STRICT'), 'TLP:AMBER+STRICT')
  assert.equal(tlpAuMoins('TLP:RED', 'TLP:AMBER'), 'TLP:RED')
  assert.equal(tlpAuMoins('TLP:GREEN', null), 'TLP:GREEN')
})
