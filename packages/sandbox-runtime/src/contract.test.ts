import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DIAGNOSTIC_OPS,
  RESULT_LINE_PREFIX,
  parseSandboxResult,
  sandboxJobSchema,
  sandboxResultSchema,
} from './contract';

// ─── Job schema (worker → container) ─────────────────────────────────────────

test('sandboxJobSchema accepts the selftest op', () => {
  assert.deepEqual(sandboxJobSchema.parse({ op: 'selftest' }), { op: 'selftest' });
});

test('sandboxJobSchema accepts diagnostic ops with their params (and defaults)', () => {
  assert.deepEqual(sandboxJobSchema.parse({ op: 'sleep', durationMs: 100 }), {
    op: 'sleep',
    durationMs: 100,
  });
  // alloc.holdMs defaults
  assert.deepEqual(sandboxJobSchema.parse({ op: 'alloc', megabytes: 8 }), {
    op: 'alloc',
    megabytes: 8,
    holdMs: 10_000,
  });
  // netcheck target.timeoutMs defaults
  const netcheck = sandboxJobSchema.parse({
    op: 'netcheck',
    targets: [{ label: 'gw', host: 'gateway', port: 5432 }],
  });
  assert.equal(netcheck.op, 'netcheck');
  assert.equal(netcheck.op === 'netcheck' && netcheck.targets[0]?.timeoutMs, 4_000);
});

test('sandboxJobSchema rejects an unknown op', () => {
  assert.equal(sandboxJobSchema.safeParse({ op: 'rm-rf' }).success, false);
});

test('sandboxJobSchema rejects a sleep with a non-positive duration', () => {
  assert.equal(sandboxJobSchema.safeParse({ op: 'sleep', durationMs: 0 }).success, false);
});

test('DIAGNOSTIC_OPS lists exactly the gated ops (selftest is NOT gated)', () => {
  assert.deepEqual([...DIAGNOSTIC_OPS].sort(), ['alloc', 'netcheck', 'sleep']);
  assert.equal((DIAGNOSTIC_OPS as readonly string[]).includes('selftest'), false);
});

// ─── Result schema + stdout extraction (container → worker) ───────────────────

const validSelftestResult = {
  op: 'selftest' as const,
  engine: { layer1Outcome: 'vulnerable', probesExecuted: 14, findingsCount: 1, findings: [] },
  chromium: { executablePath: '/x/chrome', present: true, launched: true, version: 'Chromium/1.0' },
  runtime: { node: 'v24.0.0', user: 'uid=1001' },
  // T-FIX.9: contract snapshot baked into the image at build time; required field.
  contract: { scanTypes: ['ai-llm-attack', 'web-app-vuln', 'api-scan'] },
};

test('parseSandboxResult extracts and validates the prefixed result line', () => {
  const stdout = `some library noise\n${RESULT_LINE_PREFIX}${JSON.stringify(validSelftestResult)}\n`;
  const result = parseSandboxResult(stdout);
  assert.equal(result.op, 'selftest');
});

test('parseSandboxResult takes the LAST result line so stray earlier output cannot shadow it', () => {
  const decoy = { op: 'error' as const, message: 'decoy' };
  const stdout =
    `${RESULT_LINE_PREFIX}${JSON.stringify(decoy)}\n` +
    `${RESULT_LINE_PREFIX}${JSON.stringify(validSelftestResult)}\n`;
  assert.equal(parseSandboxResult(stdout).op, 'selftest');
});

test('parseSandboxResult throws when no result line is present', () => {
  assert.throws(() => parseSandboxResult('just logs, no result\n'), /no result line/i);
});

test('parseSandboxResult throws on malformed JSON', () => {
  assert.throws(() => parseSandboxResult(`${RESULT_LINE_PREFIX}{not json}`), /not valid JSON/i);
});

test('parseSandboxResult throws (ZodError) on a schema-invalid result', () => {
  // op present but findings shape is wrong → schema rejects (CLAUDE.md §3).
  const bad = { op: 'selftest', engine: { layer1Outcome: 'x' } };
  assert.throws(
    () => parseSandboxResult(`${RESULT_LINE_PREFIX}${JSON.stringify(bad)}`),
    (err: Error) => err.name === 'ZodError',
  );
});

test('sandboxResultSchema accepts an error envelope', () => {
  assert.deepEqual(sandboxResultSchema.parse({ op: 'error', message: 'boom' }), {
    op: 'error',
    message: 'boom',
  });
});
