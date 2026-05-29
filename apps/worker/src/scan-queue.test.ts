import './test-env'; // MUST be first: sets env before '@anthrion/shared' validates it.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Queue } from 'bullmq';
import type { ConnectionOptions } from 'bullmq';

import {
  DEFAULT_SCAN_JOB_OPTIONS,
  ScanQueueProducer,
  SCAN_JOB_NAME,
  scanJobPayloadSchema,
} from '@anthrion/shared';

import type { ScanResultStore } from './persistence/scan-repository';
import type { ScanProgressPublisher } from './progress/progress-publisher';
import { createScanWorker, type ScanProcessorDeps } from './scan-consumer';
import type { SandboxOutcome, ScanSandbox } from './sandbox/manager';
import type { ScanRunResult, ScanRunSucceeded } from './scan-runner';
import type { ArtifactStore } from './storage/artifact-store';

// Real Redis (docker-compose publishes it on 6380). No mocked Redis — this mirrors
// the real-Postgres integration tests in T1.2. Run `docker compose up -d` first.
const REDIS_URL = process.env['REDIS_URL'] ?? 'redis://localhost:6380';

// Passing connection OPTIONS (not a shared instance) makes BullMQ create and own a
// connection per Queue/Worker, and close it on `.close()` — so the test process exits.
const connection = { url: REDIS_URL, maxRetriesPerRequest: null } satisfies ConnectionOptions;

const uniqueQueueName = (): string =>
  `scan-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

// Stub sandbox: this file tests the QUEUE plumbing (producer → Redis → consumer →
// result), not the sandbox. The real DockerSandboxManager is tested against real
// Docker in sandbox.test.ts / scan-e2e.test.ts. Injecting a stub keeps these tests
// fast and Docker-free (not a mock left on the production path — it is test-only DI).
const stubSandbox = (outcome: SandboxOutcome): ScanSandbox => ({
  runScanInSandbox: () => Promise.resolve(outcome),
});

// No-op persistence stubs: this file does not test DB/MinIO (that is scan-store.test.ts,
// against real Postgres + MinIO). Keeps the queue tests dependent on Redis only.
const noopStore: ScanResultStore = {
  markRunning: () => Promise.resolve(),
  saveSucceeded: () => Promise.resolve(),
  saveFailed: () => Promise.resolve(),
  addArtifact: () => Promise.resolve(),
};
const noopArtifacts: ArtifactStore = {
  ensureBucket: () => Promise.resolve(),
  uploadScanLog: (scanId) =>
    Promise.resolve({ bucket: 'test', objectKey: `scans/${scanId}/scan-log.json`, contentType: 'application/json', sizeBytes: 0 }),
  uploadReportPdf: (scanId) =>
    Promise.resolve({ bucket: 'test', objectKey: `scans/${scanId}/report.pdf`, contentType: 'application/pdf', sizeBytes: 0 }),
};
const noopProgress: ScanProgressPublisher = {
  publishStage: () => Promise.resolve(),
  publishLifecycle: () => Promise.resolve(),
};
const deps = (sandbox: ScanSandbox): ScanProcessorDeps => ({
  sandbox,
  store: noopStore,
  artifacts: noopArtifacts,
  progress: noopProgress,
});

// ─── Payload validation (Zod) — no Redis needed ─────────────────────────────

test('scanJobPayloadSchema accepts an AI endpoint scan and keeps fields intact', () => {
  const input = {
    scanId: 'scan-1',
    scanType: 'ai-llm-attack',
    target: { kind: 'endpoint', url: 'https://agent.example/chat', model: 'agent-x' },
  };
  // deepEqual proves every field survives parsing and nothing extra is injected.
  assert.deepEqual(scanJobPayloadSchema.parse(input), input);
});

test('scanJobPayloadSchema accepts an AI endpoint scan with optional apiKey auth (no default headerName)', () => {
  const input = {
    scanId: 'scan-auth',
    scanType: 'ai-llm-attack',
    target: { kind: 'endpoint', url: 'https://agent.example', auth: { type: 'apiKey', value: 'k-1' } },
  };
  // headerName has no wire default — the engine applies `X-API-Key` when it builds
  // ScanConfig. deepEqual confirms parsing does NOT inject a headerName here.
  assert.deepEqual(scanJobPayloadSchema.parse(input), input);
});

test('scanJobPayloadSchema accepts an AI system-prompt scan', () => {
  const input = {
    scanId: 'scan-2',
    scanType: 'ai-llm-attack',
    target: { kind: 'system-prompt', prompt: 'You are a banking assistant.' },
  };
  assert.deepEqual(scanJobPayloadSchema.parse(input), input);
});

test('scanJobPayloadSchema accepts a web-app-vuln scan', () => {
  const input = {
    scanId: 'scan-3',
    scanType: 'web-app-vuln',
    target: { url: 'https://app.example' },
  };
  assert.deepEqual(scanJobPayloadSchema.parse(input), input);
});

test('scanJobPayloadSchema accepts an api-scan with a raw target (Phase 1.5 T-A1.3)', () => {
  const input = {
    scanId: 'scan-api-raw',
    scanType: 'api-scan',
    target: { kind: 'raw', url: 'https://api.example/v1/users/42' },
  };
  assert.deepEqual(scanJobPayloadSchema.parse(input), input);
});

test('scanJobPayloadSchema accepts an api-scan with a spec target (pre-parsed document object)', () => {
  const input = {
    scanId: 'scan-api-spec',
    scanType: 'api-scan',
    target: {
      kind: 'spec',
      document: { openapi: '3.0.0', info: { title: 't', version: '1' }, paths: {} },
      baseUrl: 'https://api.example',
    },
  };
  assert.deepEqual(scanJobPayloadSchema.parse(input), input);
});

test('scanJobPayloadSchema rejects an api-scan spec target with a string document (SSRF guard, T-A1.1)', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({
      scanId: 'x',
      scanType: 'api-scan',
      target: { kind: 'spec', document: 'https://evil.example/spec.yaml' },
    }).success,
    false,
  );
});

test('scanJobPayloadSchema rejects an api-scan raw target with an invalid URL', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({
      scanId: 'x',
      scanType: 'api-scan',
      target: { kind: 'raw', url: 'not-a-url' },
    }).success,
    false,
  );
});

test('scanJobPayloadSchema rejects a missing scanId', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({
      scanType: 'web-app-vuln',
      target: { url: 'https://app.example' },
    }).success,
    false,
  );
});

test('scanJobPayloadSchema rejects an unknown scanType', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({ scanId: 'x', scanType: 'sql-scan', target: {} }).success,
    false,
  );
});

test('scanJobPayloadSchema rejects an endpoint target with an invalid URL', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({
      scanId: 'x',
      scanType: 'ai-llm-attack',
      target: { kind: 'endpoint', url: 'not-a-url' },
    }).success,
    false,
  );
});

test('scanJobPayloadSchema rejects an empty system prompt', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({
      scanId: 'x',
      scanType: 'ai-llm-attack',
      target: { kind: 'system-prompt', prompt: '' },
    }).success,
    false,
  );
});

test('scanJobPayloadSchema rejects a missing target', () => {
  assert.equal(
    scanJobPayloadSchema.safeParse({ scanId: 'x', scanType: 'ai-llm-attack' }).success,
    false,
  );
});

// ─── Job options (retry/backoff) ────────────────────────────────────────────

test('DEFAULT_SCAN_JOB_OPTIONS sets attempts and exponential backoff', () => {
  assert.equal(DEFAULT_SCAN_JOB_OPTIONS.attempts, 3);
  assert.equal(DEFAULT_SCAN_JOB_OPTIONS.backoff.type, 'exponential');
  assert.equal(DEFAULT_SCAN_JOB_OPTIONS.backoff.delay, 5_000);
});

// ─── Producer-side validation (real Queue connection) ───────────────────────

test('producer rejects an invalid payload BEFORE enqueue', { timeout: 20_000 }, async () => {
  const producer = new ScanQueueProducer(connection, uniqueQueueName());
  try {
    await assert.rejects(
      // missing target — must fail Zod validation, nothing enqueued
      () => producer.enqueueScan({ scanId: 'bad', scanType: 'ai-llm-attack' }),
      (err: Error) => err.name === 'ZodError',
    );
  } finally {
    await producer.close();
  }
});

// ─── End-to-end: producer → real Redis → consumer ───────────────────────────

test('a job flows producer → Redis → consumer and yields a scan result', { timeout: 20_000 }, async () => {
  const queueName = uniqueQueueName();
  const producer = new ScanQueueProducer(connection, queueName);

  // The stub returns a `completed` sandbox outcome carrying a scan result, so the
  // consumer maps it to a `succeeded` ScanRunResult — proving the queue→worker→result
  // path without touching Docker (the real sandbox path is in scan-e2e.test.ts).
  const outcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'stub',
    exitCode: 0,
    durationMs: 5,
    result: {
      op: 'scan',
      findings: [],
      report: {
        scanType: 'ai-llm-attack',
        passedLayer1: true,
        layer1Outcome: 'passed',
        layer1Stats: { total: 0, executed: 0, detected: 0, clean: 0, notExecuted: 0 },
        layer2Ran: false,
        layer2StoppedReason: 'not-run',
        budgetUsed: 0,
        budgetCap: 20_000,
      },
    },
  };
  const worker = createScanWorker(connection, queueName, deps(stubSandbox(outcome)));
  const cleanup = new Queue(queueName, { connection });

  const payload = {
    scanId: 'e2e-1',
    scanType: 'ai-llm-attack' as const,
    target: { kind: 'endpoint' as const, url: 'https://agent.example/chat', model: 'agent-x' },
  };

  try {
    const received = await new Promise<{ result: ScanRunResult; attempts: number | undefined }>(
      (resolve, reject) => {
        worker.on('completed', (job, result) => resolve({ result, attempts: job.opts.attempts }));
        worker.on('failed', (_job, err) => reject(err));
        producer.enqueueScan(payload).catch(reject);
      },
    );

    // The consumer ran the (stubbed) scan and produced a succeeded result for our scanId.
    assert.equal(received.result.status, 'succeeded');
    assert.equal(received.result.scanId, 'e2e-1');
    assert.equal(received.result.scanType, 'ai-llm-attack');
    // The retry option rode along with the job.
    assert.equal(received.attempts, DEFAULT_SCAN_JOB_OPTIONS.attempts);
  } finally {
    await worker.close();
    await producer.close();
    await cleanup.obliterate({ force: true });
    await cleanup.close();
  }
});

// ─── Report generation wiring (T6.1) ────────────────────────────────────────

test('the consumer fires generateReport for a successful scan, never for a failure (T6.1)', { timeout: 20_000 }, async () => {
  const succeededOutcome: SandboxOutcome = {
    status: 'completed',
    containerName: 'stub',
    exitCode: 0,
    durationMs: 5,
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
  };
  const failedOutcome: SandboxOutcome = {
    status: 'error',
    containerName: 'stub',
    exitCode: 1,
    durationMs: 5,
    message: 'simulated failure',
    stderr: '',
  };

  async function runOnce(outcome: SandboxOutcome, scanId: string): Promise<{ result: ScanRunResult; reportCalls: ScanRunSucceeded[] }> {
    const queueName = uniqueQueueName();
    const producer = new ScanQueueProducer(connection, queueName);
    const reportCalls: ScanRunSucceeded[] = [];
    const processorDeps: ScanProcessorDeps = {
      ...deps(stubSandbox(outcome)),
      generateReport: (result) => {
        reportCalls.push(result);
        return Promise.resolve();
      },
    };
    const worker = createScanWorker(connection, queueName, processorDeps);
    const cleanup = new Queue(queueName, { connection });
    try {
      const result = await new Promise<ScanRunResult>((resolve, reject) => {
        worker.on('completed', (_job, r) => resolve(r));
        worker.on('failed', (_job, err) => reject(err));
        producer.enqueueScan({ scanId, scanType: 'web-app-vuln', target: { url: 'https://app.example' } }).catch(reject);
      });
      return { result, reportCalls };
    } finally {
      await worker.close();
      await producer.close();
      await cleanup.obliterate({ force: true });
      await cleanup.close();
    }
  }

  // Success → report generation runs exactly once, with the succeeded result.
  const ok = await runOnce(succeededOutcome, 'report-ok');
  assert.equal(ok.result.status, 'succeeded');
  assert.equal(ok.reportCalls.length, 1);
  assert.equal(ok.reportCalls[0]?.scanId, 'report-ok');

  // Failure → no report (FAILED scans get no PDF — locked decision).
  const failed = await runOnce(failedOutcome, 'report-fail');
  assert.equal(failed.result.status, 'failed');
  assert.equal(failed.reportCalls.length, 0);
});

// ─── Consumer-side validation ───────────────────────────────────────────────

test('the consumer rejects an invalid payload it receives from the queue', { timeout: 20_000 }, async () => {
  const queueName = uniqueQueueName();
  // Enqueue a malformed payload directly (bypassing the producer's validation) to
  // prove the CONSUMER validates what it pulls off the queue (CLAUDE.md §3).
  const rawQueue = new Queue(queueName, { connection });
  // Stub sandbox is never reached: payload validation throws first. Injecting it keeps
  // this test free of any real Docker coupling.
  const unreachableOutcome: SandboxOutcome = {
    status: 'error',
    containerName: 'stub',
    exitCode: 1,
    durationMs: 0,
    message: 'should not be called',
    stderr: '',
  };
  const worker = createScanWorker(connection, queueName, deps(stubSandbox(unreachableOutcome)));

  try {
    const failure = await new Promise<Error>((resolve, reject) => {
      worker.on('failed', (_job, err) => resolve(err));
      worker.on('completed', () => reject(new Error('invalid payload was processed as success')));
      // attempts: 1 → fails fast without waiting on backoff retries
      rawQueue
        .add(SCAN_JOB_NAME, { scanId: 'malformed', scanType: 'ai-llm-attack' }, { attempts: 1 })
        .catch(reject);
    });

    assert.equal(failure.name, 'ZodError');
  } finally {
    await worker.close();
    await rawQueue.obliterate({ force: true });
    await rawQueue.close();
  }
});
