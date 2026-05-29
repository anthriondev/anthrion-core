import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { Web3Chain } from './config';
import type { OnChainContext, OnChainContextProvider } from './web3-onchain-context';
import {
  NO_L3_DETECTIONS,
  type Web3L3Detection,
  type Web3L3Probe,
} from './web3-l3-probe';
import {
  DEFAULT_WEB3_L3_PROBE_TIMEOUT_MS,
  WEB3_L3_ELEVATED_RISK_CATEGORY,
  WEB3_L3_ELEVATED_RISK_ID_PREFIX,
  WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND,
  runWeb3Layer3,
} from './web3-l3';
import { WEB3_L3_PROBES } from './web3-l3-probes';
import type { ContractAddress, ReferencedContract } from './web3-types';

/**
 * Runner-level tests for T-A3.5: outcome state machine, per-address coverage
 * gaps, per-probe timeout, and — most importantly — the §4 hybrid aggregate
 * composition. Per-probe rules live in `web3-l3-probes.test.ts`.
 *
 * The runner is exercised with stub `OnChainContextProvider`s and stub probe
 * sets so the tests stay deterministic and free of the live RPC / explorer
 * machinery (those are covered in `web3-onchain-context-loader.test.ts`).
 */

const ADDR_A = '0xaaaa000000000000000000000000000000000001' as ContractAddress;
const ADDR_B = '0xbbbb000000000000000000000000000000000002' as ContractAddress;
const ADDR_C = '0xcccc000000000000000000000000000000000003' as ContractAddress;

function refContract(address: ContractAddress): ReferencedContract {
  return { address, origin: 'wallet-request', walletRequestSequence: 0, walletRequestMethod: 'eth_call' };
}

function stubContext(overrides: Partial<OnChainContext> & { address: ContractAddress }): OnChainContext {
  return {
    address: overrides.address,
    chain: overrides.chain ?? 'ethereum',
    kind: overrides.kind ?? 'contract',
    proxy: overrides.proxy ?? null,
    admin: overrides.admin ?? null,
    explorer: overrides.explorer ?? null,
    availability: overrides.availability ?? 'complete',
    unavailableReason: overrides.unavailableReason ?? null,
  };
}

function createStubProvider(input: {
  chain?: Web3Chain;
  byAddress: ReadonlyMap<string, OnChainContext>;
}): OnChainContextProvider {
  return {
    chain: input.chain ?? 'ethereum',
    async getContractContext(address) {
      const key = address.toLowerCase();
      const found = input.byAddress.get(key);
      if (found !== undefined) return found;
      // Default to unavailable so a missing entry surfaces honestly, not as a
      // silent "complete with empty fields" result.
      return stubContext({
        address,
        availability: 'unavailable',
        unavailableReason: 'stub provider: address not configured',
      });
    },
  };
}

/** Synthesise a probe that fires unconditionally with the given category +
 * severity. Used to keep aggregate-composition tests independent of the real
 * probes' input-shape requirements. */
function makeAlwaysFireProbe(input: {
  id: string;
  category: Web3L3Probe['category'];
  severity: Web3L3Probe['severity'];
}): Web3L3Probe {
  return {
    id: input.id,
    technique: `stub probe ${input.id}`,
    category: input.category,
    severity: input.severity,
    title: `Stub probe ${input.id} fired`,
    description: `Stub probe ${input.id} fires unconditionally.`,
    recommendation: 'Test recommendation.',
    evaluate(context): readonly Web3L3Detection[] {
      return [
        {
          address: context.address,
          rationale: `Stub ${input.id} fired on ${context.address}.`,
          evidence: `stub=${input.id}`,
        },
      ];
    },
  };
}

function makeSilentProbe(input: {
  id: string;
  category: Web3L3Probe['category'];
}): Web3L3Probe {
  return {
    id: input.id,
    technique: `stub silent ${input.id}`,
    category: input.category,
    severity: 'Low',
    title: `Stub silent ${input.id}`,
    description: 'Silent stub probe.',
    recommendation: 'Test recommendation.',
    evaluate() {
      return NO_L3_DETECTIONS;
    },
  };
}

// ─── Single source of truth for runner constants ────────────────────────────

test('WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND matches the agreed-upon slug', () => {
  // The slug is the runner-worker contract — rename deliberately, both sides.
  assert.equal(WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND, 'web3-l3-on-chain-context-unavailable');
});

test('WEB3_L3_ELEVATED_RISK_CATEGORY uses the aggregate slug from owaspWeb3CategorySchema', () => {
  assert.equal(WEB3_L3_ELEVATED_RISK_CATEGORY, 'elevated-risk-contract');
  assert.equal(WEB3_L3_ELEVATED_RISK_ID_PREFIX, 'web3:l3:elevated-risk-contract');
});

// ─── no-contracts-observed outcome ──────────────────────────────────────────

test('runWeb3Layer3: emits no-contracts-observed when input is empty', async () => {
  const provider = createStubProvider({ byAddress: new Map() });
  const report = await runWeb3Layer3([], provider);
  assert.equal(report.outcome, 'no-contracts-observed');
  assert.equal(report.findings.length, 0);
  assert.equal(report.results.length, 0);
  assert.equal(report.addressCoverageGaps.length, 0);
  assert.equal(report.stats.addressCount, 0);
  assert.equal(report.stats.total, 0);
});

// ─── per-address coverage gap on context unavailable ────────────────────────

test('runWeb3Layer3: address with unavailable context emits coverage gap + not-executed results', async () => {
  const provider = createStubProvider({
    byAddress: new Map([
      [
        ADDR_A.toLowerCase(),
        stubContext({
          address: ADDR_A,
          availability: 'unavailable',
          unavailableReason: 'rate limited',
        }),
      ],
    ]),
  });
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider);
  assert.equal(report.outcome, 'passed-with-gaps');
  assert.equal(report.findings.length, 0);
  assert.equal(report.addressCoverageGaps.length, 1);
  assert.equal(report.addressCoverageGaps[0]?.address, ADDR_A);
  assert.equal(report.addressCoverageGaps[0]?.kind, WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND);
  assert.equal(report.addressCoverageGaps[0]?.reason, 'rate limited');
  assert.equal(report.results.length, WEB3_L3_PROBES.length);
  for (const result of report.results) {
    assert.equal(result.status, 'not-executed');
    assert.equal(result.address, ADDR_A);
    assert.match(result.rationale, /rate limited/);
  }
  assert.equal(report.stats.unavailableAddressCount, 1);
  assert.equal(report.stats.aggregateFindingCount, 0);
});

// ─── passed outcome ─────────────────────────────────────────────────────────

test('runWeb3Layer3: passed when every probe is clean on every available context', async () => {
  const provider = createStubProvider({
    byAddress: new Map([
      [
        ADDR_A.toLowerCase(),
        stubContext({
          address: ADDR_A,
          // Verified, EOA-not-admin, no proxy, no recent deployment, no name collision.
          explorer: {
            sourceVerified: true,
            contractName: 'GoodContract',
            compilerVersion: '0.8.20',
            deployerAddress: null,
            deploymentTxHash: null,
            deploymentTimestamp: Math.floor(Date.now() / 1000) - 365 * 86_400,
          },
          admin: { owner: null, pendingOwner: null, ownerKind: 'not-exposed' },
        }),
      ],
    ]),
  });
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider);
  assert.equal(report.outcome, 'passed');
  assert.equal(report.findings.length, 0);
  assert.equal(report.addressCoverageGaps.length, 0);
  assert.equal(report.stats.clean, WEB3_L3_PROBES.length);
});

// ─── per-probe timeout ──────────────────────────────────────────────────────

test('runWeb3Layer3: per-probe timeout marks the probe not-executed with timeout reason', async () => {
  const slowProbe: Web3L3Probe = {
    id: 'web3:l3:test-slow',
    technique: 'slow stub',
    category: 'contract-source-not-verified',
    severity: 'Medium',
    title: 'Slow probe',
    description: 'Slow probe.',
    recommendation: 'Test.',
    async evaluate() {
      await new Promise((r) => setTimeout(r, 200));
      return NO_L3_DETECTIONS;
    },
  };
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, {
    probes: [slowProbe],
    probeTimeoutMs: 25,
  });
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0]?.status, 'not-executed');
  assert.match(report.results[0]?.error ?? '', /timed out after 25ms/);
  assert.equal(report.stats.notExecuted, 1);
  assert.equal(report.outcome, 'passed-with-gaps');
});

// ─── Default per-probe timeout is reasonable ────────────────────────────────

test('DEFAULT_WEB3_L3_PROBE_TIMEOUT_MS is 10s — L3 probes do not network round-trip', () => {
  assert.equal(DEFAULT_WEB3_L3_PROBE_TIMEOUT_MS, 10_000);
});

// ─── De-duplication of addresses ────────────────────────────────────────────

test('runWeb3Layer3: de-duplicates input contracts by lower-cased address', async () => {
  const calls: string[] = [];
  const provider: OnChainContextProvider = {
    chain: 'ethereum',
    async getContractContext(address) {
      calls.push(address.toLowerCase());
      return stubContext({ address });
    },
  };
  // Two references to ADDR_A (one upper-cased, one lower-cased), plus ADDR_B.
  // ContractAddress is lower-cased by schema, so simulate the "harvester saw
  // the same address twice" path by passing two entries of the same value.
  const report = await runWeb3Layer3(
    [refContract(ADDR_A), refContract(ADDR_A), refContract(ADDR_B)],
    provider,
  );
  assert.equal(report.stats.addressCount, 2);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.sort(), [ADDR_A.toLowerCase(), ADDR_B.toLowerCase()].sort());
});

// ─── §4 hybrid aggregate composition ────────────────────────────────────────

test('aggregate: 1 indicator → no aggregate finding emitted', async () => {
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const onlyOneFiringProbe = makeAlwaysFireProbe({
    id: 'web3:l3:stub-low',
    category: 'recent-contract-deployment',
    severity: 'Low',
  });
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, {
    probes: [onlyOneFiringProbe],
  });
  assert.equal(report.findings.length, 1);
  assert.equal(report.stats.aggregateFindingCount, 0);
  assert.notEqual(report.findings[0]?.category, WEB3_L3_ELEVATED_RISK_CATEGORY);
});

test('aggregate: 2 indicators on same contract → emits 1 elevated-risk-contract finding', async () => {
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-low',
      category: 'recent-contract-deployment',
      severity: 'Low',
    }),
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-medium',
      category: 'contract-source-not-verified',
      severity: 'Medium',
    }),
  ];
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, { probes });
  // 2 per-indicator + 1 aggregate = 3 findings.
  assert.equal(report.findings.length, 3);
  assert.equal(report.stats.aggregateFindingCount, 1);
  const aggregate = report.findings.find((f) => f.category === WEB3_L3_ELEVATED_RISK_CATEGORY);
  assert.ok(aggregate !== undefined);
  // max(Low, Medium) = Medium; elevate one tier → High.
  assert.equal(aggregate.severity, 'High');
  // Evidence explicitly lists the contributing indicator slugs — no hidden math.
  assert.match(aggregate.evidence.output, /indicators present:/);
  assert.match(aggregate.evidence.output, /recent-contract-deployment/);
  assert.match(aggregate.evidence.output, /contract-source-not-verified/);
  // Per-contract aggregate id is stable + scoped to the address.
  assert.equal(aggregate.id, `${WEB3_L3_ELEVATED_RISK_ID_PREFIX}#address=${ADDR_A}`);
});

test('aggregate: severity = max(individual) +1 tier capped at High (Low+Low → Medium)', async () => {
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-a',
      category: 'recent-contract-deployment',
      severity: 'Low',
    }),
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-b',
      category: 'eoa-admin-single-key',
      severity: 'Low',
    }),
  ];
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, { probes });
  const aggregate = report.findings.find((f) => f.category === WEB3_L3_ELEVATED_RISK_CATEGORY);
  assert.ok(aggregate !== undefined);
  // max(Low, Low) = Low; elevate → Medium.
  assert.equal(aggregate.severity, 'Medium');
});

test('aggregate: severity caps at High when contributors include a High indicator', async () => {
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-medium',
      category: 'contract-source-not-verified',
      severity: 'Medium',
    }),
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-high',
      category: 'token-impersonation-indicator',
      severity: 'High',
    }),
  ];
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, { probes });
  const aggregate = report.findings.find((f) => f.category === WEB3_L3_ELEVATED_RISK_CATEGORY);
  assert.ok(aggregate !== undefined);
  // max(Medium, High) = High; elevate would target Critical but cap → High.
  // Critical is NEVER synthesised from aggregation (T-A3.5 §4 lock).
  assert.equal(aggregate.severity, 'High');
});

test('aggregate: separate addresses with 1 indicator each → no aggregates', async () => {
  const provider = createStubProvider({
    byAddress: new Map([
      [ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })],
      [ADDR_B.toLowerCase(), stubContext({ address: ADDR_B })],
    ]),
  });
  // ONE probe firing across two addresses = one indicator per address, not two
  // indicators on the same address. No aggregate.
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-one',
      category: 'recent-contract-deployment',
      severity: 'Medium',
    }),
  ];
  const report = await runWeb3Layer3(
    [refContract(ADDR_A), refContract(ADDR_B)],
    provider,
    { probes },
  );
  assert.equal(report.findings.length, 2);
  assert.equal(report.stats.aggregateFindingCount, 0);
});

test('aggregate: per-contract aggregation — each contract gets its own aggregate when ≥2 indicators hit', async () => {
  const provider = createStubProvider({
    byAddress: new Map([
      [ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })],
      [ADDR_B.toLowerCase(), stubContext({ address: ADDR_B })],
      [ADDR_C.toLowerCase(), stubContext({ address: ADDR_C })],
    ]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-x',
      category: 'recent-contract-deployment',
      severity: 'Low',
    }),
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-y',
      category: 'contract-source-not-verified',
      severity: 'Medium',
    }),
  ];
  const report = await runWeb3Layer3(
    [refContract(ADDR_A), refContract(ADDR_B), refContract(ADDR_C)],
    provider,
    { probes },
  );
  // 2 indicators × 3 addresses = 6 per-indicator findings + 3 aggregates = 9 total.
  assert.equal(report.findings.length, 9);
  assert.equal(report.stats.aggregateFindingCount, 3);
  // Each aggregate id is unique to its address.
  const aggregateIds = report.findings
    .filter((f) => f.category === WEB3_L3_ELEVATED_RISK_CATEGORY)
    .map((f) => f.id);
  assert.deepEqual(new Set(aggregateIds).size, 3);
});

test('aggregate: per-indicator findings are RETAINED (not replaced by the aggregate)', async () => {
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-low',
      category: 'recent-contract-deployment',
      severity: 'Low',
    }),
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-med',
      category: 'contract-source-not-verified',
      severity: 'Medium',
    }),
  ];
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, { probes });
  // The two per-indicator findings appear ALONGSIDE the aggregate.
  const perIndicatorCategories = report.findings
    .filter((f) => f.category !== WEB3_L3_ELEVATED_RISK_CATEGORY)
    .map((f) => f.category)
    .sort();
  assert.deepEqual(perIndicatorCategories, ['contract-source-not-verified', 'recent-contract-deployment']);
});

test('aggregate: silent-probe + firing-probe combo does NOT trip aggregation (need ≥2 firing)', async () => {
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-fires',
      category: 'recent-contract-deployment',
      severity: 'High',
    }),
    makeSilentProbe({ id: 'web3:l3:stub-silent', category: 'eoa-admin-single-key' }),
  ];
  const report = await runWeb3Layer3([refContract(ADDR_A)], provider, { probes });
  assert.equal(report.findings.length, 1);
  assert.equal(report.stats.aggregateFindingCount, 0);
});

// ─── Progress events ────────────────────────────────────────────────────────

test('runWeb3Layer3: emits started + completed progress events with aggregate count', async () => {
  const events: Array<{ phase: string; status: string; detail?: Record<string, unknown> }> = [];
  const provider = createStubProvider({
    byAddress: new Map([[ADDR_A.toLowerCase(), stubContext({ address: ADDR_A })]]),
  });
  const probes = [
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-1',
      category: 'recent-contract-deployment',
      severity: 'Low',
    }),
    makeAlwaysFireProbe({
      id: 'web3:l3:stub-2',
      category: 'contract-source-not-verified',
      severity: 'Medium',
    }),
  ];
  await runWeb3Layer3([refContract(ADDR_A)], provider, {
    probes,
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
  assert.equal(events[0]?.phase, 'web3-l3');
  assert.equal(events[0]?.status, 'started');
  assert.equal(events[1]?.status, 'completed');
  assert.equal(events[1]?.detail?.aggregateFindings, 1);
  assert.equal(events[1]?.detail?.outcome, 'vulnerable');
});
