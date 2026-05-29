import './test-env'; // MUST be first: sets env before '@anthrion/shared' validates it.

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { Queue } from 'bullmq';
import type { ConnectionOptions } from 'bullmq';
import { Client as MinioClient } from 'minio';

import { createPrismaClient, type PrismaClient, type ScanType } from '@anthrion/db';
import type { Finding } from '@anthrion/scan-engine';
import { ScanQueueProducer, env } from '@anthrion/shared';

import { persistScanResult } from './persistence/persist-result';
import { ScanRepository, type ScanResultStore } from './persistence/scan-repository';
import type { ScanProgressPublisher } from './progress/progress-publisher';
import { loadSandboxConfig } from './sandbox/config';
import { docker, dockerAvailable, imageExists, removeContainer } from './sandbox/docker';
import { DockerSandboxManager, type SandboxOutcome, type ScanSandbox } from './sandbox/manager';
import { createScanWorker } from './scan-consumer';
import type { ScanRunResult } from './scan-runner';
import { MinioArtifactStore, type ArtifactStore } from './storage/artifact-store';

/**
 * Scan persistence tests (T3.4, Part D) — REAL Postgres + MinIO + Redis + Docker.
 *
 * The QUEUED `Scan` row is created directly here, simulating what `api` will do at
 * `POST /scans` (T4.1 — PLACEHOLDER). The worker then drives RUNNING → DONE/FAILED.
 */

const FIXTURE = `${__dirname}/../test-fixtures/fake-target-server.cjs`;
const TARGET_NAME = `anthrion-store-target-${Date.now()}`;
const REDIS_URL = process.env['REDIS_URL'] ?? 'redis://localhost:6380';
const connection = { url: REDIS_URL, maxRetriesPerRequest: null } satisfies ConnectionOptions;
const uniqueQueue = (): string => `scan-store-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const config = loadSandboxConfig();
const manager = new DockerSandboxManager(config);
const prisma: PrismaClient = createPrismaClient(env.DATABASE_URL);
const artifacts = new MinioArtifactStore();
const repo = new ScanRepository(prisma);
// Progress is proven in scan-progress.test.ts; persistence tests use a no-op publisher.
const noopProgress: ScanProgressPublisher = {
  publishStage: () => Promise.resolve(),
  publishLifecycle: () => Promise.resolve(),
};
// Independent MinIO client just for verifying objects really landed.
const minioVerify = new MinioClient({
  endPoint: env.MINIO_ENDPOINT,
  port: env.MINIO_PORT,
  useSSL: false,
  accessKey: env.MINIO_ACCESS_KEY,
  secretKey: env.MINIO_SECRET_KEY,
});

// ─── Pure unit test (no infra): artifact-upload failure handling (Part B) ────

test('persistScanResult: a failed artifact upload does not undo the result and is not silent', async () => {
  const calls = { saved: 0, addArtifact: 0 };
  const store: ScanResultStore = {
    markRunning: () => Promise.resolve(),
    saveSucceeded: () => {
      calls.saved += 1;
      return Promise.resolve();
    },
    saveFailed: () => Promise.resolve(),
    addArtifact: () => {
      calls.addArtifact += 1;
      return Promise.resolve();
    },
  };
  const throwingArtifacts: ArtifactStore = {
    ensureBucket: () => Promise.resolve(),
    uploadScanLog: () => Promise.reject(new Error('minio unreachable')),
    uploadReportPdf: () => Promise.reject(new Error('minio unreachable')),
  };
  const result: ScanRunResult = {
    status: 'succeeded',
    scanId: 'unit-1',
    scanType: 'web-app-vuln',
    findings: [],
    report: {
      scanType: 'web-app-vuln',
      pageLoaded: true,
      outcome: 'passed',
      stats: { total: 1, executed: 1, detected: 0, clean: 1, notExecuted: 0 },
    },
    durationMs: 1,
  };

  // Must NOT throw — the authoritative result stands even if the blob upload fails.
  await persistScanResult({ store, artifacts: throwingArtifacts }, result);
  assert.equal(calls.saved, 1, 'the result was persisted');
  assert.equal(calls.addArtifact, 0, 'no dangling artifact row was created');
});

describe('scan persistence (real Postgres + MinIO + Redis + Docker)', () => {
  let skipReason: string | undefined;
  let targetIp = '';
  let userId = '';
  const createdScanIds: string[] = [];

  async function createQueuedScan(input: {
    scanType: ScanType;
    targetUrl?: string;
    targetKind?: string;
  }): Promise<string> {
    // PLACEHOLDER for T4.1: api will create the QUEUED row at POST /scans.
    const scan = await prisma.scan.create({
      data: {
        status: 'QUEUED',
        scanType: input.scanType,
        userId,
        ...(input.targetUrl !== undefined ? { targetUrl: input.targetUrl } : {}),
        ...(input.targetKind !== undefined ? { targetKind: input.targetKind } : {}),
      },
    });
    createdScanIds.push(scan.id);
    return scan.id;
  }

  before(async () => {
    if (!(await dockerAvailable())) {
      skipReason = 'Docker daemon not available';
      return;
    }
    if (!(await imageExists(config.image))) {
      skipReason = `image "${config.image}" not built — run scripts/build-sandbox-image.sh`;
      return;
    }
    await artifacts.ensureBucket();
    await manager.sweepOrphans();
    await docker(['network', 'inspect', config.network]).catch(() =>
      docker(['network', 'create', '--driver', 'bridge', config.network]),
    );
    await docker([
      'run', '-d', '--name', TARGET_NAME,
      '--label', 'anthrion.test-target=1',
      '--network', config.network,
      '-v', `${FIXTURE}:/srv/fake.cjs:ro`,
      '--entrypoint', 'node',
      config.image, '/srv/fake.cjs',
    ]);
    targetIp = (
      await docker(['inspect', '-f', `{{(index .NetworkSettings.Networks "${config.network}").IPAddress}}`, TARGET_NAME])
    ).trim();
    for (let i = 0; i < 40; i += 1) {
      try {
        await fetch(`http://${targetIp}:8080/`);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    const user = await prisma.user.create({ data: { privyUserId: `t3.4-test-${Date.now()}` } });
    userId = user.id;
  });

  after(async () => {
    if (skipReason === undefined) {
      await removeContainer(TARGET_NAME);
      await manager.sweepOrphans();
      // Cascade deletes findings/artifacts via the scan FK; then remove the test user.
      await prisma.scan.deleteMany({ where: { id: { in: createdScanIds } } });
      if (userId !== '') {
        await prisma.user.delete({ where: { id: userId } }).catch(() => undefined);
      }
    }
    await prisma.$disconnect();
  });

  // ── markRunning transition point (Part C.1) ──────────────────────────────

  test('markRunning transitions QUEUED → RUNNING and sets startedAt', async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = await createQueuedScan({ scanType: 'WEB_APP_VULN', targetUrl: 'https://x.example' });
    await repo.markRunning(scanId);
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    assert.equal(scan.status, 'RUNNING');
    assert.notEqual(scan.startedAt, null);
  });

  // ── Finding mapping is lossless (Part C.3 / Context §3) ───────────────────

  test('saveSucceeded maps engine Finding → DB Finding losslessly and sets DONE', async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = await createQueuedScan({ scanType: 'AI_LLM_ATTACK', targetKind: 'system-prompt' });
    const finding: Finding = {
      id: 'layer1:mapping-test',
      severity: 'Critical',
      category: 'prompt-injection',
      title: 'Title',
      description: 'Description',
      evidence: { input: 'the attack', output: 'the response', metadata: { probeId: 'p1', technique: 't' } },
      recommendation: 'Fix it',
    };
    await repo.saveSucceeded(scanId, [finding]);

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId }, include: { findings: true } });
    assert.equal(scan.status, 'DONE');
    assert.notEqual(scan.finishedAt, null);
    assert.equal(scan.findings.length, 1);
    const row = scan.findings[0];
    assert.ok(row);
    assert.equal(row.engineId, finding.id);
    assert.equal(row.severity, 'CRITICAL'); // mapped from 'Critical'
    assert.equal(row.category, finding.category);
    assert.equal(row.title, finding.title);
    assert.equal(row.description, finding.description);
    assert.equal(row.recommendation, finding.recommendation);
    // Structured evidence survived the JSON round-trip with no information loss.
    assert.deepEqual(row.evidence, {
      input: finding.evidence.input,
      output: finding.evidence.output,
      metadata: finding.evidence.metadata,
    });
  });

  // ── Success: full path via the queue → DONE + findings + MinIO artifact ───

  test('web scan job → DONE, findings persisted, transcript artifact in MinIO + DB ref', { timeout: 120_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const targetUrl = `http://${targetIp}:8080/`;
    const scanId = await createQueuedScan({ scanType: 'WEB_APP_VULN', targetUrl });
    const queueName = uniqueQueue();
    const producer = new ScanQueueProducer(connection, queueName);
    const worker = createScanWorker(connection, queueName, { sandbox: manager, store: repo, artifacts, progress: noopProgress });
    const cleanup = new Queue(queueName, { connection });

    try {
      const result = await new Promise<ScanRunResult>((resolveResult, reject) => {
        worker.on('completed', (_job, r) => resolveResult(r));
        worker.on('failed', (_job, err) => reject(err));
        producer.enqueueScan({ scanId, scanType: 'web-app-vuln', target: { url: targetUrl } }).catch(reject);
      });

      assert.equal(result.status, 'succeeded');
      if (result.status !== 'succeeded') return;
      assert.ok(result.findings.length > 0);

      const scan = await prisma.scan.findUniqueOrThrow({
        where: { id: scanId },
        include: { findings: true, artifacts: true },
      });
      // Status + timing transitions (QUEUED→RUNNING→DONE).
      assert.equal(scan.status, 'DONE');
      assert.notEqual(scan.startedAt, null);
      assert.notEqual(scan.finishedAt, null);
      assert.equal(scan.failureReason, null);
      // Findings persisted, count matches the engine result.
      assert.equal(scan.findings.length, result.findings.length);
      // Lossless spot-check of one finding against the engine output.
      const engineFinding = result.findings[0];
      assert.ok(engineFinding);
      const row = scan.findings.find((f) => f.engineId === engineFinding.id);
      assert.ok(row, 'each engine finding is persisted by engineId');
      assert.equal(row.severity, engineFinding.severity.toUpperCase());
      assert.equal(row.title, engineFinding.title);
      assert.deepEqual(row.evidence, {
        input: engineFinding.evidence.input,
        output: engineFinding.evidence.output,
        ...(engineFinding.evidence.metadata !== undefined ? { metadata: engineFinding.evidence.metadata } : {}),
      });
      // Artifact row + the object really exists in MinIO with the recorded size.
      assert.equal(scan.artifacts.length, 1);
      const artifact = scan.artifacts[0];
      assert.ok(artifact);
      assert.equal(artifact.type, 'SCAN_LOG');
      const stat = await minioVerify.statObject(artifact.bucket, artifact.objectKey);
      assert.equal(stat.size, artifact.sizeBytes);
      assert.ok(stat.size > 0);
    } finally {
      await worker.close();
      await producer.close();
      await cleanup.obliterate({ force: true });
      await cleanup.close();
    }
  });

  // ── Failure: FAILED + reason, NOT "DONE with 0 findings" (Part C.2) ───────

  test('failed scan job → FAILED with reason and zero findings (never "DONE 0 findings")', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = await createQueuedScan({
      scanType: 'AI_LLM_ATTACK',
      targetUrl: 'https://agent.example',
      targetKind: 'endpoint',
    });
    // Deterministic failure via a stub sandbox returning `error`. The real sandbox
    // failure modes are proven with real Docker in sandbox.test.ts; here the SUBJECT is
    // persistence of a failed result.
    const errorSandbox: ScanSandbox = {
      runScanInSandbox: (): Promise<SandboxOutcome> =>
        Promise.resolve({
          status: 'error',
          containerName: 'stub',
          exitCode: 1,
          durationMs: 5,
          message: 'simulated sandbox error',
          stderr: '',
        }),
    };
    const queueName = uniqueQueue();
    const producer = new ScanQueueProducer(connection, queueName);
    const worker = createScanWorker(connection, queueName, { sandbox: errorSandbox, store: repo, artifacts, progress: noopProgress });
    const cleanup = new Queue(queueName, { connection });

    try {
      const result = await new Promise<ScanRunResult>((resolveResult, reject) => {
        worker.on('completed', (_job, r) => resolveResult(r));
        worker.on('failed', (_job, err) => reject(err));
        producer
          .enqueueScan({ scanId, scanType: 'ai-llm-attack', target: { kind: 'endpoint', url: 'https://agent.example' } })
          .catch(reject);
      });

      assert.equal(result.status, 'failed');

      const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId }, include: { findings: true } });
      assert.equal(scan.status, 'FAILED');
      assert.notEqual(scan.failureReason, null);
      assert.match(scan.failureReason ?? '', /sandbox-error/);
      assert.equal(scan.findings.length, 0); // failed ≠ "DONE with 0 findings"
      assert.notEqual(scan.finishedAt, null);
    } finally {
      await worker.close();
      await producer.close();
      await cleanup.obliterate({ force: true });
      await cleanup.close();
    }
  });
});
