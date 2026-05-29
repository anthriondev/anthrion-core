import assert from 'node:assert/strict';
import { test } from 'node:test';

import { scanDetailResponseSchema, type FindingResponse } from '@anthrion/shared/scan-api';

import {
  WEB3_LAYER_SLUGS,
  countBySeverity,
  partitionWeb3Findings,
  sortFindings,
  toBadgeSeverity,
  web3FindingLayer,
} from './findings';

function finding(id: string, severity: FindingResponse['severity']): FindingResponse {
  return {
    id,
    severity,
    category: 'prompt-injection',
    title: `finding ${id}`,
    description: 'desc',
    evidence: { input: 'in', output: 'out' },
    recommendation: 'fix',
  };
}

test('toBadgeSeverity maps every wire severity to its Badge form', () => {
  assert.equal(toBadgeSeverity('CRITICAL'), 'Critical');
  assert.equal(toBadgeSeverity('HIGH'), 'High');
  assert.equal(toBadgeSeverity('MEDIUM'), 'Medium');
  assert.equal(toBadgeSeverity('LOW'), 'Low');
  assert.equal(toBadgeSeverity('INFO'), 'Info');
});

test('countBySeverity tallies all five levels (zero-filled)', () => {
  const counts = countBySeverity([finding('1', 'HIGH'), finding('2', 'HIGH'), finding('3', 'INFO')]);
  assert.deepEqual(counts, { Critical: 0, High: 2, Medium: 0, Low: 0, Info: 1 });
});

test('sortFindings orders most-severe first and is stable within a severity', () => {
  const input = [
    finding('a', 'LOW'),
    finding('b', 'CRITICAL'),
    finding('c', 'HIGH'),
    finding('d', 'CRITICAL'), // same severity as b → must stay after b (stable)
    finding('e', 'INFO'),
  ];
  const ids = sortFindings(input).map((f) => f.id);
  assert.deepEqual(ids, ['b', 'd', 'c', 'a', 'e']);
});

test('sortFindings does not mutate its input', () => {
  const input = [finding('a', 'LOW'), finding('b', 'CRITICAL')];
  sortFindings(input);
  assert.deepEqual(
    input.map((f) => f.id),
    ['a', 'b'],
  );
});

test('an unknown severity is rejected at the data boundary (not silently mapped)', () => {
  // This is where "unknown severity" is handled: the api-client validates getScan with
  // this schema, so a bad severity becomes a clear invalid-response error upstream and
  // never reaches toBadgeSeverity.
  const bad = {
    id: 'scan_1',
    status: 'DONE',
    scanType: 'ai-llm-attack',
    targetUrl: null,
    targetKind: 'system-prompt',
    failureReason: null,
    createdAt: '2026-05-25T10:00:00.000Z',
    startedAt: '2026-05-25T10:00:01.000Z',
    finishedAt: '2026-05-25T10:05:00.000Z',
    findings: [{ ...finding('1', 'INFO'), severity: 'WEIRD' }],
  };
  assert.equal(scanDetailResponseSchema.safeParse(bad).success, false);
});

// ─── Web3 finding-layer partition (Sprint A3, T-A3.8) ────────────────────────

// NOTE: the engine-side drift check (every owaspWeb3CategorySchema slug must
// map to a layer) lives in apps/worker/src/report/report-model.test.ts — the
// web app may NOT import @anthrion/scan-engine (it would pull Playwright
// into the browser bundle). The web-side and worker-side slug lists are
// duplicated on purpose; both are short and stable, and a slug missing from
// the web list still renders through the partition's `unknown` bucket
// rather than being dropped.

function f(id: string, category: string): FindingResponse {
  return {
    id,
    severity: 'MEDIUM',
    category,
    title: 't',
    description: 'd',
    evidence: { input: 'i', output: 'o' },
    recommendation: 'r',
  };
}

test('web3FindingLayer: maps L1 slugs to l1', () => {
  for (const slug of WEB3_LAYER_SLUGS.l1) {
    assert.equal(web3FindingLayer(slug), 'l1', `expected ${slug} to map to l1`);
  }
});

test('web3FindingLayer: maps L2 slugs to l2', () => {
  for (const slug of WEB3_LAYER_SLUGS.l2) {
    assert.equal(web3FindingLayer(slug), 'l2', `expected ${slug} to map to l2`);
  }
});

test('web3FindingLayer: maps L3 slugs (incl. aggregate) to l3', () => {
  for (const slug of WEB3_LAYER_SLUGS.l3) {
    assert.equal(web3FindingLayer(slug), 'l3', `expected ${slug} to map to l3`);
  }
});

test('web3FindingLayer: unknown for non-web3 categories', () => {
  assert.equal(web3FindingLayer('prompt-injection'), 'unknown');
  assert.equal(web3FindingLayer('broken-access-control'), 'unknown');
});

test('partitionWeb3Findings: groups one finding per layer', () => {
  const findings: FindingResponse[] = [
    f('a', 'wallet-approval-phishing'),
    f('b', 'dapp-frontend-integrity'),
    f('c', 'contract-source-not-verified'),
    f('d', 'elevated-risk-contract'),
    f('e', 'prompt-injection'), // unknown
  ];
  const part = partitionWeb3Findings(findings);
  assert.equal(part.l1.length, 1);
  assert.equal(part.l2.length, 1);
  assert.equal(part.l3.length, 2); // contract-source + elevated-risk-contract
  assert.equal(part.unknown.length, 1);
});

test('WEB3_LAYER_SLUGS: per-list counts match the engine taxonomy (6 L1 + 3 L2 + 6 L3-with-aggregate)', () => {
  // Drift surface: structural counts match the L1/L2/L3 blocks documented in
  // owaspWeb3CategorySchema (engine side). The engine→worker drift check
  // (against the live enum) lives in apps/worker/.../report-model.test.ts;
  // here we keep a structural assertion that the web-side list has the
  // expected shape, so an accidental omission shows up locally too.
  assert.equal(WEB3_LAYER_SLUGS.l1.size, 6);
  assert.equal(WEB3_LAYER_SLUGS.l2.size, 3);
  assert.equal(WEB3_LAYER_SLUGS.l3.size, 6); // 5 indicators + 1 aggregate.
});
