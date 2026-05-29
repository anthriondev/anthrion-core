import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';

import { findingSchema, scanConfigSchema } from '@anthrion/scan-engine';

import { runSandboxJob } from './run';

/**
 * Host-side unit tests for the in-container logic (no Docker). They prove the
 * real engine runs and produces valid findings, and that the diagnostic ops behave.
 * The full sandbox round-trip (real Docker, Chromium launch, isolation) is proven by
 * apps/worker/src/sandbox.test.ts.
 */

test('selftest runs the real Layer 1 engine and returns Zod-valid findings', async () => {
  const result = await runSandboxJob({ op: 'selftest' });
  assert.equal(result.op, 'selftest');
  if (result.op !== 'selftest') {
    return;
  }
  // The echo target makes the canary probes fire, so there must be findings.
  assert.ok(result.engine.findingsCount > 0, 'expected the engine to produce findings');
  assert.equal(result.engine.findings.length, result.engine.findingsCount);
  // Each finding is a canonical, valid Finding.
  for (const finding of result.engine.findings) {
    assert.doesNotThrow(() => findingSchema.parse(finding));
  }
  // Chromium status is reported (launch is host-dependent — only asserted in the
  // Docker test where the browser is present, so we only check the field exists).
  assert.equal(typeof result.chromium.present, 'boolean');
});

test('sleep returns after the requested duration', async () => {
  const result = await runSandboxJob({ op: 'sleep', durationMs: 20 });
  assert.deepEqual(result, { op: 'sleep', sleptMs: 20 });
});

test('netcheck reports an unreachable target as not reachable', async () => {
  const result = await runSandboxJob({
    op: 'netcheck',
    // 127.0.0.1:1 is a reserved/closed port → connection refused → not reachable.
    targets: [{ label: 'closed', host: '127.0.0.1', port: 1, timeoutMs: 1_000 }],
  });
  assert.equal(result.op, 'netcheck');
  if (result.op !== 'netcheck') {
    return;
  }
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0]?.reachable, false);
});

// ── `scan` op: AI/LLM attack scan against a local OpenAI-compatible endpoint ──
//
// The endpoint adapter uses `fetch` (no Chromium, no OpenRouter), so the AI-endpoint
// scan path runs fully on the host against a local echo server. The fake server
// echoes the user message → Layer 1 canary probes fire → real findings; Layer 2 is
// skipped (Layer 1 found issues), so no OpenRouter call is made. Web scans need
// Chromium and are proven in the Docker e2e test (apps/worker/src/scan-e2e.test.ts).

let echoServer: Server;
let echoUrl: string;
let echoBaseUrl: string;

before(async () => {
  echoServer = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      // Echo the last user message back as the assistant content (OpenAI-compatible).
      let content = '';
      try {
        const parsed: unknown = JSON.parse(body);
        if (parsed !== null && typeof parsed === 'object' && 'messages' in parsed) {
          const messages = (parsed as { messages: unknown }).messages;
          if (Array.isArray(messages) && messages.length > 0) {
            const last: unknown = messages[messages.length - 1];
            if (last !== null && typeof last === 'object' && 'content' in last) {
              const c = (last as { content: unknown }).content;
              content = typeof c === 'string' ? c : '';
            }
          }
        }
      } catch {
        content = '';
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ model: 'fake-echo', choices: [{ message: { content }, finish_reason: 'stop' }] }));
    });
  });
  await new Promise<void>((resolve) => echoServer.listen(0, '127.0.0.1', resolve));
  const { port } = echoServer.address() as AddressInfo;
  echoBaseUrl = `http://127.0.0.1:${port}`;
  echoUrl = `${echoBaseUrl}/v1/chat/completions`;
});

after(async () => {
  await new Promise<void>((resolve) => echoServer.close(() => resolve()));
});

test('scan (AI endpoint) runs the hybrid engine and returns Zod-valid findings', async () => {
  const result = await runSandboxJob({
    op: 'scan',
    config: {
      type: 'ai-llm-attack',
      target: { kind: 'endpoint', url: echoUrl },
      tokenBudget: 20_000,
    },
    // Provided but unused: the echo target makes Layer 1 detect, so Layer 2 (which
    // would call OpenRouter) is skipped. Proves the AI-endpoint path without OpenRouter.
    llm: { apiKey: 'unused-in-this-test', models: { light: 'x', heavy: 'y' } },
  });

  assert.equal(result.op, 'scan');
  if (result.op !== 'scan') {
    return;
  }
  assert.equal(result.report.scanType, 'ai-llm-attack');
  assert.ok(result.findings.length > 0, 'echoing canaries should yield Layer 1 findings');
  for (const finding of result.findings) {
    assert.doesNotThrow(() => findingSchema.parse(finding));
  }
  if (result.report.scanType === 'ai-llm-attack') {
    // Layer 1 found issues → did NOT pass → Layer 2 skipped (no OpenRouter call).
    assert.equal(result.report.passedLayer1, false);
    assert.equal(result.report.layer2Ran, false);
  }
});

// ── `scan` op: API security scan (Phase 1.5 Sprint A1, T-A1.3) ───────────────
//
// The API target adapter uses `fetch` (no Chromium, no OpenRouter, no LLM), so the
// API-scan path runs fully on the host. The echo server above already returns 200
// JSON on any URL/method, so baseline reachability succeeds and the curated probes
// (api:server-software-disclosure, api:permissive-cors, api:docs-exposed,
// api:no-rate-limit) execute against it.

test('scan (api raw) runs probes, propagates coverage and endpointCount, returns Zod-valid findings', async () => {
  const result = await runSandboxJob({
    op: 'scan',
    config: scanConfigSchema.parse({
      type: 'api-scan',
      target: { kind: 'raw', url: `${echoBaseUrl}/v1/items/1` },
    }),
  });

  assert.equal(result.op, 'scan');
  if (result.op !== 'scan') return;
  assert.equal(result.report.scanType, 'api-scan');
  if (result.report.scanType !== 'api-scan') return;
  assert.equal(result.report.coverage, 'raw');
  assert.equal(result.report.endpointCount, 1);
  // Baseline reached → outcome is one of the meaningful-coverage values, NOT
  // target-unreachable. That distinction is the whole point of T-A1.2's honesty rule.
  assert.notEqual(result.report.outcome, 'target-unreachable');
  // Every finding the engine emits is canonical and Zod-valid.
  for (const finding of result.findings) {
    assert.doesNotThrow(() => findingSchema.parse(finding));
  }
});

test('scan (api raw) maps a closed-port target to outcome=target-unreachable with zero executed probes', async () => {
  const result = await runSandboxJob({
    op: 'scan',
    config: scanConfigSchema.parse({
      type: 'api-scan',
      // 127.0.0.1:1 is a reserved/closed port → connection refused; baseline fails fast.
      target: { kind: 'raw', url: 'http://127.0.0.1:1/v1' },
      timeoutMs: 2_000,
    }),
  });

  assert.equal(result.op, 'scan');
  if (result.op !== 'scan') return;
  assert.equal(result.report.scanType, 'api-scan');
  if (result.report.scanType !== 'api-scan') return;
  assert.equal(result.report.outcome, 'target-unreachable');
  assert.equal(result.report.stats.executed, 0);
  assert.equal(result.report.stats.notExecuted, result.report.stats.total);
  // No probe ran → no finding.
  assert.equal(result.findings.length, 0);
});

test('scan (api spec) builds a spec target from an OpenAPI document and reports coverage=spec', async () => {
  const result = await runSandboxJob({
    op: 'scan',
    config: scanConfigSchema.parse({
      type: 'api-scan',
      target: {
        kind: 'spec',
        document: {
          openapi: '3.0.0',
          info: { title: 'test-api', version: '1.0.0' },
          servers: [{ url: echoBaseUrl }],
          paths: {
            '/v1/items': { get: { responses: { '200': { description: 'ok' } } } },
            '/v1/items/{id}': {
              get: {
                parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
                responses: { '200': { description: 'ok' } },
              },
            },
          },
        },
      },
    }),
  });

  assert.equal(result.op, 'scan');
  if (result.op !== 'scan') return;
  assert.equal(result.report.scanType, 'api-scan');
  if (result.report.scanType !== 'api-scan') return;
  assert.equal(result.report.coverage, 'spec');
  assert.equal(result.report.endpointCount, 2);
  assert.notEqual(result.report.outcome, 'target-unreachable');
});
