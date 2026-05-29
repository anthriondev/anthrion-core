import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ApiTargetAdapterError,
  type ApiEndpoint,
  type ApiRequest,
  type ApiResponse,
  type ApiTarget,
} from './api-target';
import type { ApiProbe } from './api-probe';
import { runApiScan } from './api-scan';

/** Same fake used in api-probes.test.ts — kept local to avoid cross-test coupling. */
class FakeApiTarget implements ApiTarget {
  readonly baseUrl: string;
  readonly coverage: 'spec' | 'raw';
  private readonly endpointList: readonly ApiEndpoint[];
  private readonly responder: (req: ApiRequest) => ApiResponse | ApiTargetAdapterError;

  constructor(opts: {
    baseUrl: string;
    coverage: 'spec' | 'raw';
    endpoints: readonly ApiEndpoint[];
    responder: (req: ApiRequest) => ApiResponse | ApiTargetAdapterError;
  }) {
    this.baseUrl = opts.baseUrl;
    this.coverage = opts.coverage;
    this.endpointList = opts.endpoints;
    this.responder = opts.responder;
  }
  endpoints(): readonly ApiEndpoint[] {
    return this.endpointList;
  }
  async request(req: ApiRequest): Promise<ApiResponse> {
    const result = this.responder(req);
    if (result instanceof ApiTargetAdapterError) throw result;
    return result;
  }
}

const endpoint: ApiEndpoint = { method: 'GET', pathTemplate: '/users/123', operationId: null };

function okResponse(extra: Partial<ApiResponse> = {}): ApiResponse {
  return { status: 200, headers: {}, body: '', bodyTruncated: false, ...extra };
}

/** Tiny custom probe set so tests don't depend on the curated list's exact behavior. */
const cleanProbe: ApiProbe = {
  id: 'api:test-clean',
  technique: 't',
  category: 'api-security-misconfiguration',
  severity: 'Low',
  title: 'Clean',
  description: 'noop',
  recommendation: 'noop',
  evaluate: async () => [],
};

const detectingProbe: ApiProbe = {
  id: 'api:test-detect',
  technique: 't',
  category: 'api-security-misconfiguration',
  severity: 'Medium',
  title: 'Detecting probe',
  description: 'always detects',
  recommendation: 'fix it',
  evaluate: async (target) => {
    const [first] = target.endpoints();
    return first === undefined
      ? []
      : [{ endpoint: first, rationale: 'detected', evidence: 'demo evidence' }];
  },
};

const throwingProbe: ApiProbe = {
  id: 'api:test-throw',
  technique: 't',
  category: 'api-security-misconfiguration',
  severity: 'Low',
  title: 'Throwing probe',
  description: 'simulates internal failure',
  recommendation: 'fix probe',
  evaluate: async () => {
    throw new Error('probe-internal boom');
  },
};

const hangingProbe: ApiProbe = {
  id: 'api:test-hang',
  technique: 't',
  category: 'api-security-misconfiguration',
  severity: 'Low',
  title: 'Hanging probe',
  description: 'hangs forever',
  recommendation: 'fix probe',
  // Promise that never resolves — verifies per-probe timeout cuts it.
  evaluate: () =>
    new Promise(() => {
      /* intentionally never resolves */
    }),
};

test('runApiScan: every probe clean → outcome=passed, zero findings', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, { probes: [cleanProbe, cleanProbe] });
  assert.equal(report.outcome, 'passed');
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.clean, 2);
  assert.equal(report.stats.detected, 0);
  assert.equal(report.stats.notExecuted, 0);
});

test('runApiScan: ≥1 probe detects → outcome=vulnerable, Zod-valid Findings', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, { probes: [detectingProbe, cleanProbe] });
  assert.equal(report.outcome, 'vulnerable');
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0]?.severity, 'Medium');
  assert.equal(report.findings[0]?.category, 'api-security-misconfiguration');
  assert.match(report.findings[0]?.id ?? '', /^api:test-detect#GET:\/users\/123$/);
});

test('runApiScan: probe throws → not-executed, never silently "clean"', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, { probes: [throwingProbe, cleanProbe] });
  assert.equal(report.outcome, 'passed-with-gaps');
  assert.equal(report.stats.notExecuted, 1);
  assert.equal(report.stats.clean, 1);
  const throwResult = report.results.find((r) => r.probeId === 'api:test-throw');
  assert.equal(throwResult?.status, 'not-executed');
  assert.match(throwResult?.error ?? '', /boom/);
});

test('runApiScan: probe hangs → cut by per-probe timeout, marked not-executed', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, {
    probes: [hangingProbe, cleanProbe],
    probeTimeoutMs: 50,
  });
  assert.equal(report.outcome, 'passed-with-gaps');
  const hangResult = report.results.find((r) => r.probeId === 'api:test-hang');
  assert.equal(hangResult?.status, 'not-executed');
  assert.match(hangResult?.error ?? '', /timed out/);
});

test('runApiScan: target unreachable on baseline → every probe not-executed, outcome=target-unreachable, NOT "safe"', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => new ApiTargetAdapterError('connection refused'),
  });
  const report = await runApiScan(target, { probes: [cleanProbe, detectingProbe] });
  assert.equal(report.outcome, 'target-unreachable');
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.notExecuted, 2);
  assert.equal(report.stats.executed, 0);
});

test('runApiScan: surfaces coverage mode + endpoint count for the report layer (raw mode honesty)', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, { probes: [cleanProbe] });
  assert.equal(report.coverage, 'raw');
  assert.equal(report.endpointCount, 1);
});

test('runApiScan: spec mode surfaces full endpoint count', async () => {
  const endpoints: ApiEndpoint[] = [
    { method: 'GET', pathTemplate: '/users', operationId: null },
    { method: 'POST', pathTemplate: '/users', operationId: 'createUser' },
    { method: 'GET', pathTemplate: '/users/{id}', operationId: null },
  ];
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'spec',
    endpoints,
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, { probes: [cleanProbe] });
  assert.equal(report.coverage, 'spec');
  assert.equal(report.endpointCount, 3);
});

test('runApiScan: emits started + completed progress events', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const events: string[] = [];
  await runApiScan(target, {
    probes: [cleanProbe],
    onProgress: (event) => events.push(`${event.phase}:${event.status}`),
  });
  assert.deepEqual(events, ['api-scan:started', 'api-scan:completed']);
});

test('runApiScan: a misbehaving onProgress callback NEVER affects the scan', async () => {
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  const report = await runApiScan(target, {
    probes: [cleanProbe],
    onProgress: () => {
      throw new Error('callback intentionally throws');
    },
  });
  assert.equal(report.outcome, 'passed');
});

test('runApiScan: caps endpoint count per probe via maxEndpointsPerProbe', async () => {
  const endpoints: ApiEndpoint[] = Array.from({ length: 50 }, (_, i) => ({
    method: 'GET' as const,
    pathTemplate: `/endpoint-${i}`,
    operationId: null,
  }));
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'spec',
    endpoints,
    responder: () => okResponse(),
  });
  // Capture endpoint count seen by the probe.
  let endpointsSeen = 0;
  const countingProbe: ApiProbe = {
    id: 'api:test-counter',
    technique: 't',
    category: 'api-security-misconfiguration',
    severity: 'Low',
    title: 'Counter',
    description: 'd',
    recommendation: 'r',
    evaluate: async (t) => {
      endpointsSeen = t.endpoints().length;
      return [];
    },
  };
  const report = await runApiScan(target, { probes: [countingProbe], maxEndpointsPerProbe: 10 });
  assert.equal(endpointsSeen, 10);
  // The report still surfaces the REAL endpoint count for honesty.
  assert.equal(report.endpointCount, 50);
});

test('runApiScan: no cap effect when endpoint count is below maxEndpointsPerProbe', async () => {
  const endpoints: ApiEndpoint[] = [
    { method: 'GET' as const, pathTemplate: '/a', operationId: null },
    { method: 'GET' as const, pathTemplate: '/b', operationId: null },
  ];
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'spec',
    endpoints,
    responder: () => okResponse(),
  });
  let endpointsSeen = 0;
  const countingProbe: ApiProbe = {
    id: 'api:test-counter2',
    technique: 't',
    category: 'api-security-misconfiguration',
    severity: 'Low',
    title: 'Counter',
    description: 'd',
    recommendation: 'r',
    evaluate: async (t) => {
      endpointsSeen = t.endpoints().length;
      return [];
    },
  };
  await runApiScan(target, { probes: [countingProbe], maxEndpointsPerProbe: 100 });
  assert.equal(endpointsSeen, 2);
});

test('runApiScan: real probe set runs end-to-end against a clean target (smoke)', async () => {
  // No findings expected: clean headers, no docs, fresh rate-limit signals.
  const target = new FakeApiTarget({
    baseUrl: 'https://api.example.com',
    coverage: 'raw',
    endpoints: [endpoint],
    responder: (req) => {
      const u = new URL(req.url);
      // 404 every well-known docs path.
      if (
        u.pathname === '/openapi.json' ||
        u.pathname === '/swagger.json' ||
        u.pathname === '/api-docs' ||
        u.pathname.startsWith('/swagger') ||
        u.pathname === '/docs' ||
        u.pathname === '/redoc' ||
        u.pathname.startsWith('/v3/api-docs') ||
        u.pathname === '/openapi.yaml' ||
        u.pathname === '/swagger.yaml'
      ) {
        return okResponse({ status: 404 });
      }
      // All other requests: 200 with rate-limit headers so no-rate-limit stays clean.
      return okResponse({ status: 200, headers: { 'x-ratelimit-remaining': '99' } });
    },
  });
  const report = await runApiScan(target);
  assert.equal(report.outcome, 'passed');
  assert.equal(report.findings.length, 0);
});
