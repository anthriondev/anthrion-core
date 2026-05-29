import assert from 'node:assert/strict';
import { test } from 'node:test';

import { severitySchema, SEVERITY_ORDER } from './severity';

test('severitySchema accepts valid enum values', () => {
  for (const value of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
    assert.equal(severitySchema.parse(value), value);
  }
});

test('severitySchema rejects values outside the enum', () => {
  assert.equal(severitySchema.safeParse('Catastrophic').success, false);
  assert.equal(severitySchema.safeParse('critical').success, false);
  assert.equal(severitySchema.safeParse(1).success, false);
});

test('SEVERITY_ORDER is sorted from most severe to least severe', () => {
  assert.deepEqual(SEVERITY_ORDER, ['Critical', 'High', 'Medium', 'Low', 'Info']);
});
