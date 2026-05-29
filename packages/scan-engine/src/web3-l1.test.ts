import assert from 'node:assert/strict';
import { test } from 'node:test';

import { findingSchema } from './finding';
import type { Web3L1Probe } from './web3-l1-probe';
import {
  DEFAULT_WEB3_L1_PROBE_TIMEOUT_MS,
  WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND,
  runWeb3Layer1,
} from './web3-l1';
import { WEB3_L1_PROBES } from './web3-l1-probes';
import { SELECTOR_ERC20_APPROVE, MAX_UINT256_HEX_LOWER } from './web3-l1-probe';
import type { Web3DAppTarget } from './web3-target';
import type { WalletRequest } from './web3-types';
import type { Web3Chain } from './config';

/**
 * Node-side tests for the L1 runner (T-A3.3).
 *
 * Probe-level tests live in `web3-l1-probes.test.ts`; this file covers the
 * RUNNER contract: no-interactive-flow gap, normal "passed" path, mixed
 * detection + clean + not-executed status mix, per-probe timeout, progress
 * events, and stable per-detection finding ids.
 */

function createStubTarget(input: {
  chain: Web3Chain;
  walletRequests: readonly WalletRequest[];
}): Web3DAppTarget {
  const fail = (name: string): never => {
    throw new Error(`stub Web3DAppTarget: runner touched \`${name}\` — L1 should be wallet-request-only`);
  };
  return {
    chain: input.chain,
    requestedUrl: 'https://stub.invalid/',
    finalUrl: 'https://stub.invalid/',
    status: 200,
    responseHeaders: {},
    isHttps: true,
    cookies: () => fail('cookies()'),
    securityDetails: () => fail('securityDetails()'),
    html: () => fail('html()'),
    resources: () => fail('resources()'),
    walletRequests: () => Promise.resolve(input.walletRequests),
    referencedContracts: () => Promise.resolve([]),
    observedInteractiveFlow: () => Promise.resolve(input.walletRequests.length > 0),
  };
}

function req(method: string, params: unknown, sequence = 0): WalletRequest {
  return {
    sequence,
    method,
    params,
    timestamp: 0,
    outcome: { kind: 'resolved', result: null },
  };
}

function abiAddress(addr: string): string {
  return '0'.repeat(24) + addr.toLowerCase().replace(/^0x/, '');
}

const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const SPENDER = '0xdeadbeef00000000000000000000000000000001';
const approveMaxCalldata = `${SELECTOR_ERC20_APPROVE}${abiAddress(SPENDER)}${MAX_UINT256_HEX_LOWER}`;

// ─── Single source of truth for the coverage-gap slug ───────────────────────

test('WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND matches the agreed-upon slug', () => {
  // The slug is the runner-worker contract. Rename it deliberately, both sides.
  assert.equal(WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND, 'web3-l1-no-interactive-flow-observed');
});

// ─── no-interactive-flow-observed outcome ───────────────────────────────────

test('runWeb3Layer1: emits no-interactive-flow-observed when zero wallet requests captured', async () => {
  const target = createStubTarget({ chain: 'ethereum', walletRequests: [] });
  const report = await runWeb3Layer1(target);
  assert.equal(report.outcome, 'no-interactive-flow-observed');
  assert.equal(report.observedInteractiveFlow, false);
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.walletRequestCount, 0);
  assert.equal(report.stats.notExecuted, WEB3_L1_PROBES.length);
  assert.equal(report.stats.executed, 0);
  assert.equal(report.results.length, WEB3_L1_PROBES.length);
  for (const result of report.results) {
    assert.equal(result.status, 'not-executed');
    assert.match(result.rationale, /no interactive flow observed/);
  }
});

test('runWeb3Layer1: progress callback receives the no-flow coverage gap kind', async () => {
  const events: Array<{ phase: string; status: string; detail?: Record<string, unknown> }> = [];
  const target = createStubTarget({ chain: 'ethereum', walletRequests: [] });
  await runWeb3Layer1(target, {
    onProgress: (event) => {
      const record: { phase: string; status: string; detail?: Record<string, unknown> } = {
        phase: event.phase,
        status: event.status,
      };
      if (event.detail !== undefined) record.detail = event.detail;
      events.push(record);
    },
  });
  const completed = events.find((e) => e.status === 'completed');
  assert.ok(completed, 'expected a completed progress event');
  assert.equal(completed.phase, 'web3-l1');
  assert.equal(completed.detail?.outcome, 'no-interactive-flow-observed');
  assert.equal(completed.detail?.coverageGapKind, WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND);
});

// ─── vulnerable outcome (one probe detects) ─────────────────────────────────

test('runWeb3Layer1: emits vulnerable + Zod-valid Finding when a probe detects', async () => {
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: approveMaxCalldata }], 0),
    ],
  });
  const report = await runWeb3Layer1(target);
  assert.equal(report.outcome, 'vulnerable');
  assert.equal(report.observedInteractiveFlow, true);
  assert.equal(report.findings.length, 1);
  const finding = report.findings[0];
  assert.ok(finding);
  // Zod-validated before leaving the engine.
  assert.doesNotThrow(() => findingSchema.parse(finding));
  assert.equal(finding.category, 'wallet-approval-phishing');
  assert.equal(finding.severity, 'High');
  // Finding id is stable per offending wallet request — `${probeId}#seq=${sequence}`.
  assert.equal(finding.id, 'web3:l1:wallet-approval-phishing#seq=0');
  assert.match(finding.evidence.input, /eth_sendTransaction \(sequence 0\)/);
  // Per-probe results carry the one detection result + 5 clean.
  const detectedResults = report.results.filter((r) => r.status === 'detected');
  const cleanResults = report.results.filter((r) => r.status === 'clean');
  const notExecuted = report.results.filter((r) => r.status === 'not-executed');
  assert.equal(detectedResults.length, 1);
  assert.equal(cleanResults.length, WEB3_L1_PROBES.length - 1);
  assert.equal(notExecuted.length, 0);
  assert.equal(report.stats.walletRequestCount, 1);
});

// ─── passed outcome (interactive flow, no findings, all probes ran) ─────────

test('runWeb3Layer1: emits passed when every probe runs clean over a benign request', async () => {
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_accounts', [], 0),
      req('eth_chainId', [], 1),
      req('eth_call', [{ to: USDC, data: '0x' }, 'latest'], 2),
    ],
  });
  const report = await runWeb3Layer1(target);
  assert.equal(report.outcome, 'passed');
  assert.equal(report.observedInteractiveFlow, true);
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.clean, WEB3_L1_PROBES.length);
  assert.equal(report.stats.executed, WEB3_L1_PROBES.length);
  assert.equal(report.stats.walletRequestCount, 3);
});

// ─── passed-with-gaps outcome (a probe times out / throws) ──────────────────

test('runWeb3Layer1: a probe that throws is marked not-executed → passed-with-gaps when no other detects', async () => {
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [req('eth_accounts', [], 0)],
  });
  const explodingProbe: Web3L1Probe = {
    id: 'web3:l1:exploding-test-probe',
    technique: 'test',
    category: 'wallet-approval-phishing',
    severity: 'High',
    title: 't',
    description: 'd',
    recommendation: 'r',
    evaluate: async () => {
      throw new Error('boom');
    },
  };
  const report = await runWeb3Layer1(target, { probes: [explodingProbe] });
  assert.equal(report.outcome, 'passed-with-gaps');
  assert.equal(report.observedInteractiveFlow, true);
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0]?.status, 'not-executed');
  assert.equal(report.results[0]?.error, 'boom');
  assert.equal(report.findings.length, 0);
});

test('runWeb3Layer1: a probe that hangs is cut by the per-probe timeout', async () => {
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [req('eth_accounts', [], 0)],
  });
  const hangingProbe: Web3L1Probe = {
    id: 'web3:l1:hanging-test-probe',
    technique: 'test',
    category: 'wallet-approval-phishing',
    severity: 'High',
    title: 't',
    description: 'd',
    recommendation: 'r',
    evaluate: () => new Promise(() => { /* never resolves */ }),
  };
  const report = await runWeb3Layer1(target, { probes: [hangingProbe], probeTimeoutMs: 50 });
  assert.equal(report.outcome, 'passed-with-gaps');
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0]?.status, 'not-executed');
  assert.match(report.results[0]?.error ?? '', /timed out after 50ms/);
});

test('runWeb3Layer1: DEFAULT_WEB3_L1_PROBE_TIMEOUT_MS is the documented value', () => {
  // Acts as a drift guard for the per-probe timeout default. If this is ever
  // tightened deliberately, the constant + this assertion update together.
  assert.equal(DEFAULT_WEB3_L1_PROBE_TIMEOUT_MS, 30_000);
});

// ─── vulnerable + passed mix (interactive flow, multiple offences) ──────────

test('runWeb3Layer1: a request that triggers multiple probes produces multiple findings, each tied to seq', async () => {
  // Same eth_sendTransaction triggers `wallet-approval-phishing` (calldata is
  // approve(max)). The chain-mismatch probe is unaffected (no chainId in payload).
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: approveMaxCalldata }], 4),
      req('wallet_switchEthereumChain', [{ chainId: '0x2105' }], 9),
    ],
  });
  const report = await runWeb3Layer1(target);
  assert.equal(report.outcome, 'vulnerable');
  // Two distinct probes detected:
  const cats = new Set(report.findings.map((f) => f.category));
  assert.ok(cats.has('wallet-approval-phishing'));
  assert.ok(cats.has('mismatched-chainid-request'));
  // Finding ids carry the seq.
  const findingIds = report.findings.map((f) => f.id);
  assert.ok(findingIds.includes('web3:l1:wallet-approval-phishing#seq=4'));
  assert.ok(findingIds.includes('web3:l1:mismatched-chainid-request#seq=9'));
});

// ─── chain awareness ────────────────────────────────────────────────────────

test('runWeb3Layer1: target.chain propagates into the report', async () => {
  const target = createStubTarget({ chain: 'base', walletRequests: [] });
  const report = await runWeb3Layer1(target);
  assert.equal(report.chain, 'base');
});
