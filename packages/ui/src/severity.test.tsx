import assert from 'node:assert/strict';
import { test } from 'node:test';

import { SEVERITIES } from './severity';

// The canonical FindingSeverity enum (scan-engine src/severity.ts, T3.4). Mirrored
// here rather than imported so packages/ui stays free of the Playwright-heavy
// scan-engine dependency; this test guards the 1:1 correspondence.
const FINDING_SEVERITY = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;

test('Badge severities mirror the FindingSeverity enum (T3.4)', () => {
  assert.deepEqual([...SEVERITIES], [...FINDING_SEVERITY]);
});
