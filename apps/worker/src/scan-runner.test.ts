import './test-env'; // MUST be first: sets env before '@anthrion/shared' validates it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { crawlBudgetSchema } from '@anthrion/scan-engine';
import { scanJobCrawlBudgetSchema, type ScanJobPayload } from '@anthrion/shared';

import type { SandboxOutcome, ScanSandbox } from './sandbox/manager';
import {
  buildScanSandboxJob,
  mapPayloadToScanConfig,
  type BuildScanJobDeps,
} from './sandbox/scan-config';
import { executeScan, mapOutcomeToResult } from './scan-runner';

/**
 * Unit tests (no Docker): payload→ScanConfig mapping (Part A) and outcome→result
 * mapping (Part C / Part D). The real sandbox path is in scan-e2e.test.ts.
 */

const KNOBS: BuildScanJobDeps = {
  engine: { tokenBudget: 12_345 },
  llm: { apiKey: 'or-key', lightModel: 'light/model', heavyModel: 'heavy/model' },
  web3: {},
};

// A stub sandbox that records whether it was called, returning a fixed outcome.
function stub(outcome: SandboxOutcome): ScanSandbox & { calls: number } {
  const s = {
    calls: 0,
    runScanInSandbox(): Promise<SandboxOutcome> {
      s.calls += 1;
      return Promise.resolve(outcome);
    },
  };
  return s;
}

const completedScan = (): SandboxOutcome => ({
  status: 'completed',
  containerName: 'c',
  exitCode: 0,
  durationMs: 10,
  result: {
    op: 'scan',
    findings: [],
    report: {
      scanType: 'web-app-vuln',
      pageLoaded: true,
      outcome: 'passed',
      stats: { total: 1, executed: 1, detected: 0, clean: 1, notExecuted: 0 },
    },
  },
});

// ─── Part A: payload → ScanConfig ────────────────────────────────────────────

test('maps a web-app-vuln payload to a web ScanConfig with engine default timeouts', () => {
  const payload: ScanJobPayload = {
    scanId: 's-web',
    scanType: 'web-app-vuln',
    target: { url: 'https://app.example' },
  };
  const config = mapPayloadToScanConfig(payload, KNOBS.engine);
  assert.equal(config.type, 'web-app-vuln');
  if (config.type !== 'web-app-vuln') return;
  assert.equal(config.target.url, 'https://app.example');
  // Loose per-operation timeout guards come from engine defaults (T2.6).
  assert.equal(config.timeouts.navigationMs, 30_000);
  assert.equal(config.timeouts.probeMs, 10_000);
});

test('maps an AI endpoint payload to an AI ScanConfig with the env token budget', () => {
  const payload: ScanJobPayload = {
    scanId: 's-ai',
    scanType: 'ai-llm-attack',
    target: { kind: 'endpoint', url: 'https://agent.example', model: 'm' },
  };
  const config = mapPayloadToScanConfig(payload, KNOBS.engine);
  assert.equal(config.type, 'ai-llm-attack');
  if (config.type !== 'ai-llm-attack') return;
  assert.equal(config.tokenBudget, 12_345);
  assert.equal(config.target.kind, 'endpoint');
  if (config.target.kind === 'endpoint') {
    assert.equal(config.target.url, 'https://agent.example');
  }
});

test('maps an AI endpoint payload with apiKey auth, applying the engine header default', () => {
  const payload: ScanJobPayload = {
    scanId: 's-sp',
    scanType: 'ai-llm-attack',
    target: {
      kind: 'endpoint',
      url: 'https://agent.example',
      auth: { type: 'apiKey', value: 'k' },
    },
  };
  const config = mapPayloadToScanConfig(payload, KNOBS.engine);
  if (config.type !== 'ai-llm-attack' || config.target.kind !== 'endpoint') {
    assert.fail('expected ai endpoint config');
    return;
  }
  // The engine schema applies the default header name when none was given on the wire.
  assert.equal(config.target.auth?.type, 'apiKey');
  if (config.target.auth?.type === 'apiKey') {
    assert.equal(config.target.auth.headerName, 'X-API-Key');
  }
});

test('buildScanSandboxJob attaches llm config for AI scans and omits it for web scans', () => {
  const ai = buildScanSandboxJob(
    { scanId: 'a', scanType: 'ai-llm-attack', target: { kind: 'system-prompt', prompt: 'You are a bot.' } },
    KNOBS,
  );
  assert.equal(ai.op, 'scan');
  if (ai.op === 'scan') {
    assert.notEqual(ai.llm, undefined);
    assert.equal(ai.llm?.models.heavy, 'heavy/model');
  }

  const web = buildScanSandboxJob({ scanId: 'w', scanType: 'web-app-vuln', target: { url: 'https://x.example' } }, KNOBS);
  assert.equal(web.op === 'scan' && web.llm, undefined);
});

test('maps an api-scan raw payload to an api ScanConfig with engine default timeoutMs/bodyCap (no token budget)', () => {
  const payload: ScanJobPayload = {
    scanId: 's-api-raw',
    scanType: 'api-scan',
    target: { kind: 'raw', url: 'https://api.example/users/1' },
  };
  const config = mapPayloadToScanConfig(payload, KNOBS.engine);
  assert.equal(config.type, 'api-scan');
  if (config.type !== 'api-scan') return;
  assert.equal(config.target.kind, 'raw');
  if (config.target.kind === 'raw') {
    assert.equal(config.target.url, 'https://api.example/users/1');
  }
  // Engine defaults applied by schema — values come from scan-engine config (T-A1.1).
  assert.ok(config.timeoutMs > 0);
  assert.ok(config.bodyCaptureMaxChars > 0);
});

test('maps an api-scan spec payload to an api ScanConfig (document object pre-parsed by api layer)', () => {
  const payload: ScanJobPayload = {
    scanId: 's-api-spec',
    scanType: 'api-scan',
    target: {
      kind: 'spec',
      document: { openapi: '3.0.0', info: { title: 't', version: '1' }, paths: {} },
      baseUrl: 'https://api.example',
    },
  };
  const config = mapPayloadToScanConfig(payload, KNOBS.engine);
  assert.equal(config.type, 'api-scan');
  if (config.type !== 'api-scan') return;
  assert.equal(config.target.kind, 'spec');
  if (config.target.kind === 'spec') {
    assert.equal(config.target.baseUrl, 'https://api.example');
  }
});

test('buildScanSandboxJob omits llm for api-scan (api scan has no LLM, T-A1.1)', () => {
  const api = buildScanSandboxJob(
    {
      scanId: 'api-1',
      scanType: 'api-scan',
      target: { kind: 'raw', url: 'https://api.example/v1/items' },
    },
    KNOBS,
  );
  assert.equal(api.op, 'scan');
  assert.equal(api.op === 'scan' && api.llm, undefined);
});

test('buildScanSandboxJob throws for an AI scan with no configured OpenRouter key', () => {
  assert.throws(
    () =>
      buildScanSandboxJob(
        { scanId: 'a', scanType: 'ai-llm-attack', target: { kind: 'endpoint', url: 'https://x.example' } },
        { engine: { tokenBudget: 1000 }, llm: { apiKey: '', lightModel: 'l', heavyModel: 'h' }, web3: {} },
      ),
    (err: Error) => err.name === 'ZodError',
  );
});

// ─── Crawl-budget bounds drift guard (Phase 1.5 Sprint A2) ───────────────────
//
// `crawlBudgetSchema` (scan-engine/config.ts) and `scanJobCrawlBudgetSchema`
// (shared/scan-job.ts) duplicate their `min/max` bounds on purpose — `shared`
// may not import `scan-engine` (ARCHITECTURE.md §2). Nothing else enforces
// that the two stay in sync, so this test round-trips edge values through
// both schemas and asserts they agree on what is accepted vs. rejected.
// If the engine bounds change, this test fails until the wire bounds catch
// up (or vice-versa).
//
// Note: the wire schema's fields are all `.optional()` (no defaults applied
// at the wire boundary — the engine applies defaults later). So we test
// each field's bounds in isolation by passing an EXPLICIT value, then check
// that the engine schema accepts/rejects the same explicit value.
test('crawl budget bounds: engine and wire schemas agree on accepted/rejected edge values', () => {
  // maxDepth: engine allows [0, 10] inclusive; wire MUST agree exactly.
  for (const maxDepth of [0, 1, 5, 10]) {
    assert.equal(crawlBudgetSchema.safeParse({ maxDepth }).success, true, `engine should accept maxDepth=${maxDepth}`);
    assert.equal(scanJobCrawlBudgetSchema.safeParse({ maxDepth }).success, true, `wire should accept maxDepth=${maxDepth}`);
  }
  for (const maxDepth of [-1, 11, 100]) {
    assert.equal(crawlBudgetSchema.safeParse({ maxDepth }).success, false, `engine should reject maxDepth=${maxDepth}`);
    assert.equal(scanJobCrawlBudgetSchema.safeParse({ maxDepth }).success, false, `wire should reject maxDepth=${maxDepth}`);
  }
  // maxPages: engine allows [1, 50] inclusive; wire MUST agree exactly.
  for (const maxPages of [1, 2, 10, 50]) {
    assert.equal(crawlBudgetSchema.safeParse({ maxPages }).success, true, `engine should accept maxPages=${maxPages}`);
    assert.equal(scanJobCrawlBudgetSchema.safeParse({ maxPages }).success, true, `wire should accept maxPages=${maxPages}`);
  }
  for (const maxPages of [0, -1, 51, 1000]) {
    assert.equal(crawlBudgetSchema.safeParse({ maxPages }).success, false, `engine should reject maxPages=${maxPages}`);
    assert.equal(scanJobCrawlBudgetSchema.safeParse({ maxPages }).success, false, `wire should reject maxPages=${maxPages}`);
  }
  // Non-integer values are rejected by both (Zod int).
  for (const value of [1.5, 2.7]) {
    assert.equal(crawlBudgetSchema.safeParse({ maxDepth: value }).success, false);
    assert.equal(scanJobCrawlBudgetSchema.safeParse({ maxDepth: value }).success, false);
    assert.equal(crawlBudgetSchema.safeParse({ maxPages: value }).success, false);
    assert.equal(scanJobCrawlBudgetSchema.safeParse({ maxPages: value }).success, false);
  }
});

// ─── Part C/D: outcome → result ──────────────────────────────────────────────

const webPayload: ScanJobPayload = {
  scanId: 'out-1',
  scanType: 'web-app-vuln',
  target: { url: 'https://app.example' },
};

test('completed sandbox + valid scan result → succeeded', () => {
  const result = mapOutcomeToResult(webPayload, completedScan(), 100);
  assert.equal(result.status, 'succeeded');
  assert.equal(result.scanId, 'out-1');
});

test('web-app-vuln + pageLoaded=false → FAILED with target-unreachable (T6.2 Part B decision: zero contact ≠ DONE-with-gap)', () => {
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'c',
    exitCode: 0,
    durationMs: 30_000,
    result: {
      op: 'scan',
      findings: [],
      report: {
        scanType: 'web-app-vuln',
        pageLoaded: false,
        outcome: 'page-load-failed',
        stats: { total: 15, executed: 0, detected: 0, clean: 0, notExecuted: 15 },
        loadError: 'page.goto: Timeout 30000ms exceeded.',
      },
    },
  };
  const result = mapOutcomeToResult(webPayload, outcome, 30_001);
  assert.equal(result.status, 'failed');
  if (result.status !== 'failed') return;
  assert.equal(result.reason, 'target-unreachable');
  assert.match(result.message, /could not be loaded/);
});

test('api-scan + outcome=target-unreachable → FAILED with target-unreachable (Phase 1.5 T-A1.3: zero contact ≠ DONE)', () => {
  const apiPayload: ScanJobPayload = {
    scanId: 'out-api-unreach',
    scanType: 'api-scan',
    target: { kind: 'raw', url: 'https://unreachable.example.invalid/v1' },
  };
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'c',
    exitCode: 0,
    durationMs: 5_000,
    result: {
      op: 'scan',
      findings: [],
      report: {
        scanType: 'api-scan',
        coverage: 'raw',
        endpointCount: 1,
        outcome: 'target-unreachable',
        stats: { total: 9, executed: 0, detected: 0, clean: 0, notExecuted: 9 },
      },
    },
  };
  const result = mapOutcomeToResult(apiPayload, outcome, 5_001);
  assert.equal(result.status, 'failed');
  if (result.status !== 'failed') return;
  assert.equal(result.reason, 'target-unreachable');
  assert.match(result.message, /API target unreachable/);
});

test('api-scan + outcome=passed-with-gaps → succeeded (gaps surface in report, not as job failure)', () => {
  const apiPayload: ScanJobPayload = {
    scanId: 'out-api-gaps',
    scanType: 'api-scan',
    target: { kind: 'raw', url: 'https://api.example/v1/items' },
  };
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'c',
    exitCode: 0,
    durationMs: 2_000,
    result: {
      op: 'scan',
      findings: [],
      report: {
        scanType: 'api-scan',
        coverage: 'spec',
        endpointCount: 5,
        outcome: 'passed-with-gaps',
        stats: { total: 9, executed: 7, detected: 0, clean: 7, notExecuted: 2 },
      },
    },
  };
  const result = mapOutcomeToResult(apiPayload, outcome, 2_001);
  // Gaps are not a job-level failure — they are surfaced in the report.coverage section.
  assert.equal(result.status, 'succeeded');
});

test('api-scan + outcome=passed → succeeded (clean coverage, all probes ran)', () => {
  const apiPayload: ScanJobPayload = {
    scanId: 'out-api-clean',
    scanType: 'api-scan',
    target: { kind: 'raw', url: 'https://api.example/v1/items' },
  };
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'c',
    exitCode: 0,
    durationMs: 1_000,
    result: {
      op: 'scan',
      findings: [],
      report: {
        scanType: 'api-scan',
        coverage: 'spec',
        endpointCount: 4,
        outcome: 'passed',
        stats: { total: 9, executed: 9, detected: 0, clean: 9, notExecuted: 0 },
      },
    },
  };
  const result = mapOutcomeToResult(apiPayload, outcome, 1_001);
  assert.equal(result.status, 'succeeded');
});

test('ai-llm-attack + layer1Outcome=target-unreachable → FAILED with target-unreachable', () => {
  const aiPayload: ScanJobPayload = {
    scanId: 'out-ai-unreach',
    scanType: 'ai-llm-attack',
    target: { kind: 'endpoint', url: 'https://unreachable.example.invalid' },
  };
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'c',
    exitCode: 0,
    durationMs: 10_000,
    result: {
      op: 'scan',
      findings: [],
      report: {
        scanType: 'ai-llm-attack',
        passedLayer1: false,
        layer1Outcome: 'target-unreachable',
        layer1Stats: { total: 17, executed: 0, detected: 0, clean: 0, notExecuted: 17 },
        layer2Ran: false,
        layer2StoppedReason: 'not-run',
        budgetUsed: 0,
        budgetCap: 20000,
      },
    },
  };
  const result = mapOutcomeToResult(aiPayload, outcome, 10_001);
  assert.equal(result.status, 'failed');
  if (result.status !== 'failed') return;
  assert.equal(result.reason, 'target-unreachable');
  assert.match(result.message, /no Layer 1 probe could contact/);
});

test('force-stopped (lifetime-timeout) → failed with that reason, NOT "0 findings"', () => {
  const outcome: SandboxOutcome = {
    status: 'force-stopped',
    containerName: 'c',
    reason: 'lifetime-timeout',
    exitCode: 137,
    durationMs: 300_000,
    stderr: '',
  };
  const result = mapOutcomeToResult(webPayload, outcome, 300_001);
  assert.equal(result.status, 'failed');
  if (result.status === 'failed') {
    assert.equal(result.reason, 'lifetime-timeout');
  }
});

test('force-stopped (memory-oom) → failed with memory-oom', () => {
  const outcome: SandboxOutcome = {
    status: 'force-stopped',
    containerName: 'c',
    reason: 'memory-oom',
    exitCode: 137,
    durationMs: 5_000,
    stderr: '',
  };
  const result = mapOutcomeToResult(webPayload, outcome, 5_001);
  assert.equal(result.status === 'failed' && result.reason, 'memory-oom');
});

test('error outcome → failed with sandbox-error and the message', () => {
  const outcome: SandboxOutcome = {
    status: 'error',
    containerName: 'c',
    exitCode: 1,
    durationMs: 200,
    message: 'engine blew up',
    stderr: 'trace',
  };
  const result = mapOutcomeToResult(webPayload, outcome, 201);
  assert.equal(result.status, 'failed');
  if (result.status === 'failed') {
    assert.equal(result.reason, 'sandbox-error');
    assert.match(result.message, /engine blew up/);
  }
});

test('completed but wrong result op → failed with invalid-result', () => {
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'c',
    exitCode: 0,
    durationMs: 5,
    result: {
      op: 'selftest',
      engine: { layer1Outcome: 'passed', probesExecuted: 0, findingsCount: 0, findings: [] },
      chromium: { executablePath: '', present: false, launched: false },
      runtime: { node: 'v', user: 'u' },
      contract: { scanTypes: ['ai-llm-attack', 'web-app-vuln', 'api-scan'] },
    },
  };
  const result = mapOutcomeToResult(webPayload, outcome, 6);
  assert.equal(result.status === 'failed' && result.reason, 'invalid-result');
});

// ─── executeScan: mapping error path (Part D) ────────────────────────────────

test('executeScan returns mapping-error (and never calls the sandbox) for an AI scan with no key', async () => {
  const sandbox = stub(completedScan());
  const result = await executeScan(
    { scanId: 'm', scanType: 'ai-llm-attack', target: { kind: 'endpoint', url: 'https://x.example' } },
    sandbox,
    { deps: { engine: { tokenBudget: 1000 }, llm: { apiKey: '', lightModel: 'l', heavyModel: 'h' }, web3: {} } },
  );
  assert.equal(result.status, 'failed');
  if (result.status === 'failed') {
    assert.equal(result.reason, 'mapping-error');
  }
  // The job never reached the sandbox.
  assert.equal(sandbox.calls, 0);
});

test('executeScan runs the sandbox and maps a completed outcome to succeeded', async () => {
  const sandbox = stub(completedScan());
  const result = await executeScan(webPayload, sandbox, { deps: KNOBS });
  assert.equal(result.status, 'succeeded');
  assert.equal(sandbox.calls, 1);
});
