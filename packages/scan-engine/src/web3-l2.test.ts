import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { Web3Chain } from './config';
import type { ObservedCookie, TlsSecurityDetails } from './web-probe';
import {
  DEFAULT_WEB3_L2_PROBE_TIMEOUT_MS,
  runWeb3Layer2,
} from './web3-l2';
import { WEB3_L2_PROBES } from './web3-l2-probes';
import { NO_L2_RESULT, type Web3L2Detection, type Web3L2Probe } from './web3-l2-probe';
import type { Web3DAppTarget } from './web3-target';

/**
 * Runner-level tests for T-A3.6: outcome state machine, coverage-notes
 * aggregation, per-probe timeout, progress events. Probe rules live in
 * `web3-l2-probes.test.ts`.
 *
 * Stub probes are used here so the runner is exercised independently of
 * the real DNS/CDN inputs (network-touching paths are covered by
 * web3-l2-probes.test.ts).
 */

function stubTarget(chain: Web3Chain = 'ethereum'): Web3DAppTarget {
  return {
    chain,
    requestedUrl: 'https://stub.invalid/',
    finalUrl: 'https://stub.invalid/',
    status: 200,
    responseHeaders: {},
    isHttps: true,
    cookies: () => Promise.resolve([] as readonly ObservedCookie[]),
    securityDetails: () => Promise.resolve(null as TlsSecurityDetails | null),
    html: () => Promise.resolve(''),
    resources: () => Promise.resolve([]),
    walletRequests: () => Promise.resolve([]),
    referencedContracts: () => Promise.resolve([]),
    observedInteractiveFlow: () => Promise.resolve(false),
  };
}

function makeAlwaysFireProbe(input: {
  id: string;
  category: Web3L2Probe['category'];
  severity: Web3L2Probe['severity'];
  subjectKey?: string;
}): Web3L2Probe {
  return {
    id: input.id,
    technique: `stub probe ${input.id}`,
    category: input.category,
    severity: input.severity,
    title: `Stub probe ${input.id} fired`,
    description: 'Stub probe.',
    recommendation: 'Test.',
    evaluate(): Promise<{ detections: Web3L2Detection[] }> {
      return Promise.resolve({
        detections: [
          {
            ...(input.subjectKey !== undefined ? { subjectKey: input.subjectKey } : {}),
            rationale: `Stub ${input.id} fired.`,
            evidence: `stub=${input.id}`,
          },
        ],
      });
    },
  };
}

function makeSilentProbe(input: {
  id: string;
  category: Web3L2Probe['category'];
}): Web3L2Probe {
  return {
    id: input.id,
    technique: `silent ${input.id}`,
    category: input.category,
    severity: 'Low',
    title: `Silent ${input.id}`,
    description: 'Silent stub.',
    recommendation: 'Test.',
    evaluate() {
      return Promise.resolve(NO_L2_RESULT);
    },
  };
}

function makeCoverageNoteProbe(input: {
  id: string;
  category: Web3L2Probe['category'];
  noteKind: string;
}): Web3L2Probe {
  return {
    id: input.id,
    technique: `coverage-only ${input.id}`,
    category: input.category,
    severity: 'Low',
    title: `Coverage ${input.id}`,
    description: 'Coverage stub.',
    recommendation: 'Test.',
    evaluate() {
      return Promise.resolve({
        detections: [],
        coverageNotes: [{ kind: input.noteKind, reason: `stub coverage note for ${input.id}` }],
      });
    },
  };
}

// ─── Outcome state machine ──────────────────────────────────────────────────

test('runWeb3Layer2: passed when every probe is clean and there are no coverage notes', async () => {
  const report = await runWeb3Layer2(stubTarget(), {
    probes: [
      makeSilentProbe({ id: 'web3:l2:silent-1', category: 'dapp-frontend-integrity' }),
      makeSilentProbe({ id: 'web3:l2:silent-2', category: 'known-bad-domain-reference' }),
    ],
  });
  assert.equal(report.outcome, 'passed');
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.coverageNoteCount, 0);
  assert.equal(report.stats.clean, 2);
});

test('runWeb3Layer2: passed-with-gaps when a probe surfaces a coverage note (no detection)', async () => {
  const report = await runWeb3Layer2(stubTarget(), {
    probes: [
      makeSilentProbe({ id: 'web3:l2:silent', category: 'dapp-frontend-integrity' }),
      makeCoverageNoteProbe({
        id: 'web3:l2:coverage-only',
        category: 'dapp-dns-or-tls-hygiene',
        noteKind: 'web3-l2-test-skip',
      }),
    ],
  });
  assert.equal(report.outcome, 'passed-with-gaps');
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.coverageNoteCount, 1);
  assert.equal(report.coverageNotes[0]?.kind, 'web3-l2-test-skip');
});

test('runWeb3Layer2: vulnerable when ≥1 probe detection regardless of coverage notes', async () => {
  const report = await runWeb3Layer2(stubTarget(), {
    probes: [
      makeAlwaysFireProbe({
        id: 'web3:l2:fires',
        category: 'known-bad-domain-reference',
        severity: 'High',
        subjectKey: 'host=test.invalid',
      }),
      makeCoverageNoteProbe({
        id: 'web3:l2:coverage',
        category: 'dapp-dns-or-tls-hygiene',
        noteKind: 'web3-l2-test-skip',
      }),
    ],
  });
  assert.equal(report.outcome, 'vulnerable');
  assert.equal(report.findings.length, 1);
  assert.equal(report.stats.coverageNoteCount, 1);
});

// ─── Finding id stability ───────────────────────────────────────────────────

test('runWeb3Layer2: finding ids include the subjectKey when provided', async () => {
  const report = await runWeb3Layer2(stubTarget(), {
    probes: [
      makeAlwaysFireProbe({
        id: 'web3:l2:keyed',
        category: 'dapp-frontend-integrity',
        severity: 'Medium',
        subjectKey: 'sri-missing:https://cdn.invalid/x.js',
      }),
    ],
  });
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0]?.id, 'web3:l2:keyed#subject=sri-missing:https://cdn.invalid/x.js');
});

test('runWeb3Layer2: finding ids fall back to #target when no subjectKey', async () => {
  const probe: Web3L2Probe = {
    id: 'web3:l2:target-level',
    technique: 'target-level',
    category: 'dapp-dns-or-tls-hygiene',
    severity: 'Medium',
    title: 'Target-level finding',
    description: 'Target-level.',
    recommendation: 'Test.',
    evaluate() {
      return Promise.resolve({
        detections: [{ rationale: 'fired', evidence: 'evidence' }],
      });
    },
  };
  const report = await runWeb3Layer2(stubTarget(), { probes: [probe] });
  assert.equal(report.findings[0]?.id, 'web3:l2:target-level#target');
});

// ─── Per-probe timeout ──────────────────────────────────────────────────────

test('runWeb3Layer2: per-probe timeout marks the probe not-executed', async () => {
  const slowProbe: Web3L2Probe = {
    id: 'web3:l2:slow',
    technique: 'slow stub',
    category: 'dapp-frontend-integrity',
    severity: 'Medium',
    title: 'Slow',
    description: 'Slow.',
    recommendation: 'Test.',
    async evaluate() {
      await new Promise((r) => setTimeout(r, 200));
      return NO_L2_RESULT;
    },
  };
  const report = await runWeb3Layer2(stubTarget(), {
    probes: [slowProbe],
    probeTimeoutMs: 25,
  });
  assert.equal(report.results[0]?.status, 'not-executed');
  assert.match(report.results[0]?.error ?? '', /timed out after 25ms/);
  assert.equal(report.outcome, 'passed-with-gaps');
});

test('runWeb3Layer2: throwing probe → not-executed with the error captured', async () => {
  const throwingProbe: Web3L2Probe = {
    id: 'web3:l2:throws',
    technique: 'throwing stub',
    category: 'known-bad-domain-reference',
    severity: 'High',
    title: 'Throws',
    description: 'Throws.',
    recommendation: 'Test.',
    evaluate(): Promise<never> {
      return Promise.reject(new Error('probe-internal failure'));
    },
  };
  const report = await runWeb3Layer2(stubTarget(), { probes: [throwingProbe] });
  assert.equal(report.results[0]?.status, 'not-executed');
  assert.match(report.results[0]?.error ?? '', /probe-internal failure/);
});

// ─── Default per-probe timeout ──────────────────────────────────────────────

test('DEFAULT_WEB3_L2_PROBE_TIMEOUT_MS is 60s — L2 probes can double-fetch CDN bytes', () => {
  assert.equal(DEFAULT_WEB3_L2_PROBE_TIMEOUT_MS, 60_000);
});

// ─── Progress events ────────────────────────────────────────────────────────

test('runWeb3Layer2: emits started + completed progress events', async () => {
  const events: Array<{ phase: string; status: string; detail?: Record<string, unknown> }> = [];
  await runWeb3Layer2(stubTarget(), {
    probes: [makeSilentProbe({ id: 'web3:l2:silent', category: 'dapp-frontend-integrity' })],
    onProgress: (event) => {
      const record: { phase: string; status: string; detail?: Record<string, unknown> } = {
        phase: event.phase,
        status: event.status,
      };
      if (event.detail !== undefined) record.detail = event.detail as Record<string, unknown>;
      events.push(record);
    },
  });
  assert.equal(events.length, 2);
  assert.equal(events[0]?.phase, 'web3-l2');
  assert.equal(events[0]?.status, 'started');
  assert.equal(events[1]?.status, 'completed');
  assert.equal(events[1]?.detail?.outcome, 'passed');
});

// ─── Curated probe set ──────────────────────────────────────────────────────

test('WEB3_L2_PROBES exported set: every probe has a category in the L2 block', () => {
  const allowed = new Set(['dapp-frontend-integrity', 'known-bad-domain-reference', 'dapp-dns-or-tls-hygiene']);
  for (const probe of WEB3_L2_PROBES) {
    assert.ok(allowed.has(probe.category), `probe ${probe.id} category ${probe.category} not in L2 block`);
  }
});
