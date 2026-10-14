import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { scanDir, score, WEIGHTS } from '../src/index.js';

const fx = name => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

test('weights add up to 100', () => {
  assert.equal(Object.values(WEIGHTS).reduce((a, b) => a + b, 0), 100);
});

test('a clean app scores 100 and goes live', () => {
  const r = scanDir(fx('good'));
  assert.equal(r.score, 100);
  assert.equal(r.live, true);
});

test('a risky app is blocked', () => {
  const r = scanDir(fx('bad'));
  assert.equal(r.live, false);
  assert.equal(r.criticalFail, true);
  const ids = r.results.filter(c => !c.pass).map(c => c.id).sort();
  assert.deepEqual(ids, ['dependencies', 'egress', 'patterns', 'permissions', 'policy', 'secrets']);
});

test('score never goes below zero or above 100', () => {
  const s = score([{ id: 'secrets', pass: false, findings: Array(50).fill({}) }]);
  assert.ok(s >= 0 && s <= 100);
});
