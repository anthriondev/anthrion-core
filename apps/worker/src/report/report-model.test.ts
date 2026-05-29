import '../test-env'; // MUST be first: sets env before '@anthrion/shared' validates it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { owaspWeb3CategorySchema, type Finding } from '@anthrion/scan-engine';
import type {
  AiScanReport,
  ApiScanReport,
  ScanReport,
  Web3DappScanReport,
  WebScanReport,
} from '@anthrion/sandbox-runtime';

import {
  buildReportModel,
  partitionWeb3ReportFindings,
  web3FindingLayer,
  type ReportScanMeta,
} from './report-model';

/**
 * Report model tests (T6.1) — pure, no infra. Cover the per-type incompleteness markers
 * (Option 1: any incomplete coverage, specific to its kind), severity counting/sorting,
 * the safe target description, and the §7 rule that evidence metadata is NOT carried in.
 */

const baseMeta: ReportScanMeta = {
  scanId: 'scan_abc',
  targetUrl: 'https://agent.example/v1/chat',
  targetKind: 'endpoint',
  startedAt: new Date('2026-05-26T00:00:00Z'),
  finishedAt: new Date('2026-05-26T00:01:00Z'),
};

function aiReport(overrides: Partial<AiScanReport> = {}): ScanReport {
  return {
    scanType: 'ai-llm-attack',
    passedLayer1: true,
    layer1Outcome: 'passed',
    layer1Stats: { total: 10, executed: 10, detected: 0, clean: 10, notExecuted: 0 },
    layer2Ran: true,
    layer2StoppedReason: 'completed',
    budgetUsed: 5000,
    budgetCap: 20000,
    ...overrides,
  };
}

function webReport(overrides: Partial<WebScanReport> = {}): ScanReport {
  return {
    scanType: 'web-app-vuln',
    pageLoaded: true,
    outcome: 'passed',
    stats: { total: 8, executed: 8, detected: 0, clean: 8, notExecuted: 0 },
    ...overrides,
  };
}

/** Build a default crawl-aggregate for web reports — overrides merge cleanly. */
function crawlAgg(overrides: Partial<NonNullable<WebScanReport['crawl']>> = {}): NonNullable<WebScanReport['crawl']> {
  return {
    pagesVisited: 3,
    pagesLoaded: 3,
    pagesFailed: 0,
    pagesVulnerable: 0,
    stopReason: 'completed',
    unvisitedDiscoveredCount: 0,
    robotsBlockedCount: 0,
    unvisitedDiscovered: [],
    robotsBlocked: [],
    budget: { maxDepth: 2, maxPages: 10, respectRobots: true },
    ...overrides,
  };
}

function apiReport(overrides: Partial<ApiScanReport> = {}): ScanReport {
  return {
    scanType: 'api-scan',
    coverage: 'spec',
    endpointCount: 4,
    outcome: 'passed',
    stats: { total: 9, executed: 9, detected: 0, clean: 9, notExecuted: 0 },
    ...overrides,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'layer1:x',
    severity: 'High',
    category: 'prompt-injection',
    title: 'Title',
    description: 'Description',
    evidence: { input: 'in', output: 'out' },
    recommendation: 'Fix it',
    ...overrides,
  };
}

// ── Coverage: AI scans ────────────────────────────────────────────────────────

test('AI full scan (Layer 1 passed, Layer 2 completed) is complete — no gaps', () => {
  const model = buildReportModel({ meta: baseMeta, findings: [], report: aiReport() });
  assert.equal(model.coverage.complete, true);
  assert.equal(model.coverage.gaps.length, 0);
});

test('AI scan where Layer 1 caught issues (Layer 2 gated) is complete — not a gap', () => {
  // passedLayer1 false → Layer 2 correctly skipped; this is full coverage at the right depth.
  const report = aiReport({ passedLayer1: false, layer2Ran: false, layer2StoppedReason: 'not-run' });
  const model = buildReportModel({ meta: baseMeta, findings: [finding({ severity: 'Critical' })], report });
  assert.equal(model.coverage.complete, true);
  assert.equal(model.coverage.gaps.length, 0);
});

test('AI Layer 2 budget-exhausted yields a specific budget gap', () => {
  const report = aiReport({ layer2StoppedReason: 'budget-exhausted' });
  const model = buildReportModel({ meta: baseMeta, findings: [], report });
  assert.equal(model.coverage.complete, false);
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['ai-layer2-budget-exhausted']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /budget/i);
});

test('AI Layer 2 not-run (despite passing Layer 1) yields a specific not-run gap', () => {
  const report = aiReport({ layer2Ran: false, layer2StoppedReason: 'not-run' });
  const model = buildReportModel({ meta: baseMeta, findings: [], report });
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['ai-layer2-not-run']);
});

test('AI Layer 1 not-executed probes yield a specific Layer 1 gap (can combine with Layer 2)', () => {
  const report = aiReport({
    layer1Stats: { total: 10, executed: 7, detected: 0, clean: 7, notExecuted: 3 },
    layer2StoppedReason: 'budget-exhausted',
  });
  const model = buildReportModel({ meta: baseMeta, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.deepEqual(kinds, ['ai-layer1-probes-not-executed', 'ai-layer2-budget-exhausted']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /3 of 10/);
});

// ── Coverage: web scans ───────────────────────────────────────────────────────

test('web full scan (page loaded, all probes executed) is complete', () => {
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report: webReport() });
  assert.equal(model.coverage.complete, true);
});

test('web page-load-failed yields a specific zero-coverage gap', () => {
  const report = webReport({ pageLoaded: false, outcome: 'page-load-failed', stats: { total: 8, executed: 0, detected: 0, clean: 0, notExecuted: 8 } });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['web-page-load-failed']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /NO coverage/);
});

test('web probes-not-executed yields a specific gaps marker', () => {
  const report = webReport({ outcome: 'passed-with-gaps', stats: { total: 8, executed: 6, detected: 0, clean: 6, notExecuted: 2 } });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['web-probes-not-executed']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /2 of 8/);
});

// ── Coverage: web crawl (Phase 1.5 Sprint A2) ────────────────────────────────

test('web crawl that completed fully is complete — no crawl-specific gaps', () => {
  const report = webReport({ crawl: crawlAgg() });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  assert.equal(model.coverage.complete, true);
});

test('web crawl budget-exhausted yields a specific crawl-budget gap with counts', () => {
  const report = webReport({
    crawl: crawlAgg({
      stopReason: 'budget-exhausted',
      pagesVisited: 10,
      unvisitedDiscoveredCount: 7,
      unvisitedDiscovered: ['https://t/a', 'https://t/b'],
      budget: { maxDepth: 2, maxPages: 10, respectRobots: true },
    }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('crawl-budget-exhausted'));
  const gap = model.coverage.gaps.find((g) => g.kind === 'crawl-budget-exhausted');
  assert.ok(gap);
  assert.match(gap.detail, /10/);
  assert.match(gap.detail, /7/);
});

test('web crawl with robots-blocked URLs yields a crawl-pages-not-explored gap', () => {
  const report = webReport({
    crawl: crawlAgg({ robotsBlockedCount: 3, robotsBlocked: ['https://t/a', 'https://t/b', 'https://t/c'] }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.deepEqual(kinds, ['crawl-pages-not-explored']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /3/);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /robots\.txt/i);
});

test('web crawl can combine budget-exhausted AND robots-blocked gaps', () => {
  const report = webReport({
    crawl: crawlAgg({
      stopReason: 'budget-exhausted',
      pagesVisited: 5,
      unvisitedDiscoveredCount: 4,
      robotsBlockedCount: 2,
      budget: { maxDepth: 2, maxPages: 5, respectRobots: true },
    }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('crawl-budget-exhausted'));
  assert.ok(kinds.includes('crawl-pages-not-explored'));
});

test('web crawl probe-level gaps and crawl-budget gap can coexist (independent dimensions)', () => {
  const report = webReport({
    outcome: 'passed-with-gaps',
    stats: { total: 8, executed: 6, detected: 0, clean: 6, notExecuted: 2 },
    crawl: crawlAgg({
      stopReason: 'budget-exhausted',
      pagesVisited: 2,
      unvisitedDiscoveredCount: 1,
      budget: { maxDepth: 2, maxPages: 2, respectRobots: true },
    }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('web-probes-not-executed'));
  assert.ok(kinds.includes('crawl-budget-exhausted'));
});

test('web crawl (T-FIX.7): only seed visited, no robots blocks, queue completed → crawl-no-additional-pages-found gap', () => {
  // SPA shell scenario: seed loaded fine, link extraction returned 0 in-scope links
  // (everything is client-side routed). Coverage degraded silently in B1 — we now
  // emit a marker so the report makes the degradation visible to the reader.
  const report = webReport({
    crawl: crawlAgg({
      pagesVisited: 1,
      pagesLoaded: 1,
      pagesFailed: 0,
      stopReason: 'completed',
    }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.deepEqual(kinds, ['crawl-no-additional-pages-found']);
  const gap = model.coverage.gaps[0];
  assert.match(gap?.detail ?? '', /single-page app/i);
  assert.match(gap?.detail ?? '', /start URL/);
});

test('web crawl (T-FIX.7): a real multi-page crawl (pagesVisited > 1) does NOT emit the gap', () => {
  const report = webReport({ crawl: crawlAgg({ pagesVisited: 3, pagesLoaded: 3 }) });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.equal(kinds.includes('crawl-no-additional-pages-found'), false);
  assert.equal(model.coverage.complete, true);
});

test('web crawl (T-FIX.7): seed-failed-to-load does NOT also emit the no-additional-pages gap (load-failed wins)', () => {
  // Already covered by the existing load-failed test, but make the new gap's
  // suppression explicit so a future change cannot regress both paths firing.
  const report = webReport({
    pageLoaded: false,
    outcome: 'page-load-failed',
    stats: { total: 8, executed: 0, detected: 0, clean: 0, notExecuted: 8 },
    crawl: crawlAgg({ pagesLoaded: 0, pagesFailed: 1, pagesVisited: 1 }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('web-page-load-failed'));
  assert.equal(kinds.includes('crawl-no-additional-pages-found'), false);
});

test('web crawl (T-FIX.7): pagesVisited=1 but robots-blocked > 0 → robots gap, NOT the no-additional gap', () => {
  // Robots-blocking already explains why no additional pages were scanned; emitting
  // both gaps would be redundant.
  const report = webReport({
    crawl: crawlAgg({
      pagesVisited: 1,
      pagesLoaded: 1,
      robotsBlockedCount: 2,
      robotsBlocked: ['https://t/a', 'https://t/b'],
    }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('crawl-pages-not-explored'));
  assert.equal(kinds.includes('crawl-no-additional-pages-found'), false);
});

test('web crawl whose seed never loaded → web-page-load-failed wins; no crawl-budget gap', () => {
  // Honesty-rule check: a crawl where pageLoaded=false (no page loaded across the whole
  // crawl) is reported as zero coverage, not as "budget-exhausted with partial coverage".
  const report = webReport({
    pageLoaded: false,
    outcome: 'page-load-failed',
    stats: { total: 8, executed: 0, detected: 0, clean: 0, notExecuted: 8 },
    crawl: crawlAgg({ pagesLoaded: 0, pagesFailed: 1, pagesVisited: 1 }),
  });
  const model = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report });
  const kinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(kinds.includes('web-page-load-failed'));
  assert.equal(kinds.includes('crawl-budget-exhausted'), false);
});

// ── Coverage: api-scan (Phase 1.5 Sprint A1, T-A1.3/A1.4) ────────────────────

test('api spec full scan (passed, all probes executed) is complete', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example', targetKind: 'api-spec' },
    findings: [],
    report: apiReport(),
  });
  assert.equal(model.coverage.complete, true);
});

test('api raw clean scan ALWAYS emits the api-raw-mode-shallow honesty marker', () => {
  // Even when every probe executes and finds nothing, raw mode only saw one endpoint.
  // Surfacing this is the load-bearing honesty rule for raw scans (Phase 1.5 plan).
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example/v1/items', targetKind: 'api-raw' },
    findings: [],
    report: apiReport({ coverage: 'raw', endpointCount: 1, outcome: 'passed' }),
  });
  assert.equal(model.coverage.complete, false);
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['api-raw-mode-shallow']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /single endpoint/i);
});

test('api target-unreachable yields a zero-coverage gap (NOT "safe")', () => {
  const report = apiReport({
    outcome: 'target-unreachable',
    stats: { total: 9, executed: 0, detected: 0, clean: 0, notExecuted: 9 },
  });
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example', targetKind: 'api-spec' },
    findings: [],
    report,
  });
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['api-target-unreachable']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /NO coverage/);
});

test('api probes-not-executed yields a specific gaps marker (passed-with-gaps)', () => {
  const report = apiReport({
    outcome: 'passed-with-gaps',
    stats: { total: 9, executed: 7, detected: 0, clean: 7, notExecuted: 2 },
  });
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example', targetKind: 'api-spec' },
    findings: [],
    report,
  });
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['api-probes-not-executed']);
  assert.match(model.coverage.gaps[0]?.detail ?? '', /2 of 9/);
});

test('api raw target-unreachable combines both the unreachable + shallow markers', () => {
  // Raw mode that ALSO fails baseline reachability. Both gaps are emitted — unreachable
  // is the worse signal but raw-mode is structural and must still be surfaced.
  const report = apiReport({
    coverage: 'raw',
    endpointCount: 1,
    outcome: 'target-unreachable',
    stats: { total: 9, executed: 0, detected: 0, clean: 0, notExecuted: 9 },
  });
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example/v1', targetKind: 'api-raw' },
    findings: [],
    report,
  });
  assert.deepEqual(model.coverage.gaps.map((g) => g.kind), ['api-target-unreachable', 'api-raw-mode-shallow']);
});

// ── Severity counting + sorting ───────────────────────────────────────────────

test('severity counts are exhaustive and findings are sorted most-severe first', () => {
  const findings = [
    finding({ id: 'a', severity: 'Low' }),
    finding({ id: 'b', severity: 'Critical' }),
    finding({ id: 'c', severity: 'Medium' }),
    finding({ id: 'd', severity: 'Critical' }),
  ];
  const model = buildReportModel({ meta: baseMeta, findings, report: aiReport() });
  assert.deepEqual(model.severityCounts, { Critical: 2, High: 0, Medium: 1, Low: 1, Info: 0 });
  assert.deepEqual(
    model.findings.map((f) => f.severity),
    ['Critical', 'Critical', 'Medium', 'Low'],
  );
});

// ── Disclosure (§7) ───────────────────────────────────────────────────────────

test('evidence metadata (incl. target_model) is NOT carried into the report model', () => {
  const withModelName = finding({
    evidence: { input: 'attack', output: 'response', metadata: { target_model: 'gpt-4o', technique: 't' } },
  });
  const model = buildReportModel({ meta: baseMeta, findings: [withModelName], report: aiReport() });
  const serialized = JSON.stringify(model);
  assert.doesNotMatch(serialized, /gpt-4o/);
  assert.doesNotMatch(serialized, /target_model/);
  // The actual evidence (input/output) and human fields are still present.
  const f = model.findings[0];
  assert.ok(f);
  assert.equal(f.evidenceInput, 'attack');
  assert.equal(f.evidenceOutput, 'response');
});

// ── Safe target description (§7) ──────────────────────────────────────────────

test('a pasted system-prompt target is described generically, never leaked', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: null, targetKind: 'system-prompt' },
    findings: [],
    report: aiReport(),
  });
  assert.equal(model.targetDescription, 'System prompt (provided inline)');
  assert.equal(model.targetMode, 'System prompt');
});

test('an endpoint target shows its url and mode; web target has no mode', () => {
  const ai = buildReportModel({ meta: baseMeta, findings: [], report: aiReport() });
  assert.equal(ai.targetDescription, 'https://agent.example/v1/chat');
  assert.equal(ai.targetMode, 'Endpoint');

  const web = buildReportModel({ meta: { ...baseMeta, targetKind: null }, findings: [], report: webReport() });
  assert.equal(web.targetMode, null);
  assert.equal(web.scanTypeLabel, 'Web application vulnerability scan');
});

test('api-scan describes its target and labels mode (raw vs spec)', () => {
  const raw = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example/v1/items/1', targetKind: 'api-raw' },
    findings: [],
    report: apiReport({ coverage: 'raw', endpointCount: 1 }),
  });
  assert.equal(raw.scanTypeLabel, 'API security scan');
  assert.equal(raw.targetMode, 'Raw endpoint');
  assert.equal(raw.targetDescription, 'https://api.example/v1/items/1');

  const specWithUrl = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://api.example', targetKind: 'api-spec' },
    findings: [],
    report: apiReport(),
  });
  assert.equal(specWithUrl.targetMode, 'OpenAPI/Swagger spec');
  assert.match(specWithUrl.targetDescription, /API \(spec\)/);

  // Spec-mode scans persisted with no baseUrl never leak the raw spec document into the
  // report (§7 — same posture as system-prompt scans).
  const specNoUrl = buildReportModel({
    meta: { ...baseMeta, targetUrl: null, targetKind: 'api-spec' },
    findings: [],
    report: apiReport(),
  });
  assert.equal(specNoUrl.targetDescription, 'API (OpenAPI/Swagger spec)');
});

// ─── Web3 dApp report (Sprint A3, T-A3.8) ────────────────────────────────────

function web3Report(overrides: Partial<Web3DappScanReport> = {}): ScanReport {
  return {
    scanType: 'web3-dapp',
    chain: 'ethereum',
    pageLoaded: true,
    observedInteractiveFlow: true,
    l1Outcome: 'passed',
    l1Stats: { total: 6, executed: 6, detected: 0, clean: 6, notExecuted: 0 },
    l3Outcome: 'no-contracts-observed',
    l3Stats: {
      total: 0,
      executed: 0,
      detected: 0,
      clean: 0,
      notExecuted: 0,
      addressCount: 0,
      unavailableAddressCount: 0,
      aggregateFindingCount: 0,
    },
    l2Outcome: 'passed',
    l2Stats: { total: 3, executed: 3, detected: 0, clean: 3, notExecuted: 0, coverageNoteCount: 0 },
    l3ProviderConfigured: false,
    ...overrides,
  };
}

test('web3 report: scanTypeLabel + targetMode reflect chain via targetKind=web3-base', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-base' },
    findings: [],
    report: web3Report({ chain: 'base' }),
  });
  assert.equal(model.scanType, 'web3-dapp');
  assert.equal(model.scanTypeLabel, 'Web3 dApp scan');
  assert.equal(model.targetMode, 'Base mainnet');
  assert.match(model.targetDescription, /dApp \(base\):/);
});

test('web3 report: page-load-failed → web3-page-load-failed gap surfaces honestly', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-ethereum' },
    findings: [],
    report: web3Report({ pageLoaded: false, loadError: 'navigation failed' }),
  });
  assert.equal(model.coverage.complete, false);
  const gapKinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(gapKinds.includes('web3-page-load-failed'));
});

test('web3 report: no-interactive-flow → web3-l1-no-interactive-flow-observed gap', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-ethereum' },
    findings: [],
    report: web3Report({ observedInteractiveFlow: false }),
  });
  const gapKinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(gapKinds.includes('web3-l1-no-interactive-flow-observed'));
});

test('web3 report: provider not configured → web3-l3-provider-not-configured gap', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-ethereum' },
    findings: [],
    report: web3Report({ l3ProviderConfigured: false }),
  });
  const gapKinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(gapKinds.includes('web3-l3-provider-not-configured'));
});

test('web3 report: L3 unavailable addresses → web3-l3-on-chain-context-unavailable gap (when provider IS configured)', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-ethereum' },
    findings: [],
    report: web3Report({
      l3ProviderConfigured: true,
      l3Stats: {
        total: 5,
        executed: 5,
        detected: 0,
        clean: 5,
        notExecuted: 0,
        addressCount: 3,
        unavailableAddressCount: 2,
        aggregateFindingCount: 0,
      },
    }),
  });
  const gapKinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(gapKinds.includes('web3-l3-on-chain-context-unavailable'));
});

test('web3 report: L2 coverage notes > 0 → web3-l2-subchecks-skipped gap', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-ethereum' },
    findings: [],
    report: web3Report({
      l2Stats: { total: 3, executed: 3, detected: 0, clean: 3, notExecuted: 0, coverageNoteCount: 2 },
    }),
  });
  const gapKinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(gapKinds.includes('web3-l2-subchecks-skipped'));
});

test('web3 report: per-layer probes not-executed → web3-layer-probes-not-executed gap', () => {
  const model = buildReportModel({
    meta: { ...baseMeta, targetUrl: 'https://dapp.example', targetKind: 'web3-ethereum' },
    findings: [],
    report: web3Report({
      l1Stats: { total: 6, executed: 4, detected: 0, clean: 4, notExecuted: 2 },
    }),
  });
  const gapKinds = model.coverage.gaps.map((g) => g.kind);
  assert.ok(gapKinds.includes('web3-layer-probes-not-executed'));
});

test('partitionWeb3ReportFindings: every engine slug is mapped to a layer', () => {
  // Worker-side drift check (mirrors the web-side test in apps/web/.../findings.test.ts).
  for (const slug of owaspWeb3CategorySchema.options) {
    assert.notEqual(
      web3FindingLayer(slug),
      'unknown',
      `engine slug ${slug} has no layer attribution in WEB3_LAYER_SLUGS — extend the L1/L2/L3 lists`,
    );
  }
});

test('partitionWeb3ReportFindings: groups one finding per layer', () => {
  const findings = [
    { severity: 'High' as const, category: 'wallet-approval-phishing', title: 't', description: 'd', evidenceInput: 'i', evidenceOutput: 'o', recommendation: 'r' },
    { severity: 'Medium' as const, category: 'dapp-frontend-integrity', title: 't', description: 'd', evidenceInput: 'i', evidenceOutput: 'o', recommendation: 'r' },
    { severity: 'High' as const, category: 'elevated-risk-contract', title: 't', description: 'd', evidenceInput: 'i', evidenceOutput: 'o', recommendation: 'r' },
  ];
  const part = partitionWeb3ReportFindings(findings);
  assert.equal(part.l1.length, 1);
  assert.equal(part.l2.length, 1);
  assert.equal(part.l3.length, 1);
  assert.equal(part.unknown.length, 0);
});
