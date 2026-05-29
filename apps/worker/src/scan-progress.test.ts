import './test-env'; // MUST be first: sets env before '@anthrion/shared' validates it.

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { Queue } from 'bullmq';
import type { ConnectionOptions } from 'bullmq';
import IORedis from 'ioredis';

import { ScanQueueProducer, parseScanStreamEvent, scanProgressChannel, type ScanStreamEvent } from '@anthrion/shared';

import { RedisScanProgressPublisher } from './progress/progress-publisher';
import { loadSandboxConfig } from './sandbox/config';
import { docker, dockerAvailable, imageExists, removeContainer } from './sandbox/docker';
import { DockerSandboxManager } from './sandbox/manager';
import { createScanWorker } from './scan-consumer';
import type { ScanResultStore } from './persistence/scan-repository';
import type { ScanRunResult } from './scan-runner';
import type { ArtifactStore } from './storage/artifact-store';

/**
 * Worker progress tests (T4.2, Part B) — REAL Redis (+ Docker for the end-to-end case).
 *
 * Proves the worker publishes scan progress to Redis pub/sub: the event-validation seam
 * (untrusted container output → Zod → wire event) and the full path where a real scan's
 * stage events streamed from the sandbox stdout reach the Redis channel.
 */

const REDIS_URL = process.env['REDIS_URL'] ?? 'redis://localhost:6380';

// Persistence is irrelevant here — proven in scan-store.test.ts. No-op keeps focus on progress.
const noopStore: ScanResultStore = {
  markRunning: () => Promise.resolve(),
  saveSucceeded: () => Promise.resolve(),
  saveFailed: () => Promise.resolve(),
  addArtifact: () => Promise.resolve(),
};
const noopArtifacts: ArtifactStore = {
  ensureBucket: () => Promise.resolve(),
  uploadScanLog: (scanId) =>
    Promise.resolve({ bucket: 't', objectKey: scanId, contentType: 'application/json', sizeBytes: 0 }),
  uploadReportPdf: (scanId) =>
    Promise.resolve({ bucket: 't', objectKey: `scans/${scanId}/report.pdf`, contentType: 'application/pdf', sizeBytes: 0 }),
};

/** Collect events published to a scan's channel via a dedicated subscriber connection. */
async function collectEvents(scanId: string): Promise<{ events: ScanStreamEvent[]; close: () => Promise<void> }> {
  const sub = new IORedis(REDIS_URL);
  const events: ScanStreamEvent[] = [];
  await sub.subscribe(scanProgressChannel(scanId));
  sub.on('message', (_channel, message) => {
    const event = parseScanStreamEvent(message);
    if (event !== undefined) {
      events.push(event);
    }
  });
  return {
    events,
    close: async () => {
      await sub.quit();
    },
  };
}

// ── Publisher validation (real Redis, no Docker) — Part D "event divalidasi Zod" ──

test('publisher maps a valid engine event to a wire stage event; drops invalid ones', async () => {
  const pub = new IORedis(REDIS_URL);
  const publisher = new RedisScanProgressPublisher(pub);
  const scanId = `pub-${Date.now()}`;
  const { events, close } = await collectEvents(scanId);
  try {
    // Valid engine event (as the container would emit) → published as a wire stage event.
    await publisher.publishStage(
      scanId,
      JSON.stringify({ phase: 'layer-1', status: 'started', message: 'go', detail: { probes: 3 } }),
    );
    // Invalid: not JSON, and JSON failing the schema → both dropped (not published).
    await publisher.publishStage(scanId, 'not-json');
    await publisher.publishStage(scanId, JSON.stringify({ phase: 'nope', status: 'x' }));
    await publisher.publishLifecycle(scanId, 'DONE');

    await new Promise((r) => setTimeout(r, 300));

    // Only the valid stage event + the lifecycle event got through.
    const stages = events.filter((e) => e.type === 'stage');
    const lifecycles = events.filter((e) => e.type === 'lifecycle');
    assert.equal(stages.length, 1);
    assert.equal(stages[0]?.type === 'stage' && stages[0].phase, 'layer-1');
    assert.equal(lifecycles.length, 1);
    assert.equal(lifecycles[0]?.type === 'lifecycle' && lifecycles[0].status, 'DONE');
  } finally {
    await close();
    await pub.quit();
  }
});

// ── Full path: a real scan's stage events reach Redis (Part B) ────────────────

describe('worker publishes a real scan’s progress to Redis (Docker + Redis)', () => {
  let skipReason: string | undefined;
  let targetIp = '';
  const config = loadSandboxConfig();
  const manager = new DockerSandboxManager(config);
  const connection = { url: REDIS_URL, maxRetriesPerRequest: null } satisfies ConnectionOptions;
  const pubRedis = new IORedis(REDIS_URL);
  const publisher = new RedisScanProgressPublisher(pubRedis);
  const targetName = `anthrion-progress-target-${Date.now()}`;
  const fixture = `${__dirname}/../test-fixtures/fake-target-server.cjs`;

  before(async () => {
    if (!(await dockerAvailable())) {
      skipReason = 'Docker daemon not available';
      return;
    }
    if (!(await imageExists(config.image))) {
      skipReason = `image "${config.image}" not built — run scripts/build-sandbox-image.sh`;
      return;
    }
    await manager.sweepOrphans();
    await docker(['network', 'inspect', config.network]).catch(() =>
      docker(['network', 'create', '--driver', 'bridge', config.network]),
    );
    await docker([
      'run', '-d', '--name', targetName, '--label', 'anthrion.test-target=1',
      '--network', config.network, '-v', `${fixture}:/srv/fake.cjs:ro`,
      '--entrypoint', 'node', config.image, '/srv/fake.cjs',
    ]);
    targetIp = (
      await docker(['inspect', '-f', `{{(index .NetworkSettings.Networks "${config.network}").IPAddress}}`, targetName])
    ).trim();
    for (let i = 0; i < 40; i += 1) {
      try {
        await fetch(`http://${targetIp}:8080/`);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
  });

  after(async () => {
    if (skipReason === undefined) {
      await removeContainer(targetName);
      await manager.sweepOrphans();
    }
    await pubRedis.quit();
  });

  test('a web scan streams lifecycle + stage events to the scan channel', { timeout: 120_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = `progress-web-${Date.now()}`;
    const { events, close } = await collectEvents(scanId);
    const queueName = `scan-progress-${Date.now()}`;
    const producer = new ScanQueueProducer(connection, queueName);
    const worker = createScanWorker(connection, queueName, {
      sandbox: manager,
      store: noopStore,
      artifacts: noopArtifacts,
      progress: publisher,
    });
    const cleanup = new Queue(queueName, { connection });

    try {
      const result = await new Promise<ScanRunResult>((resolveResult, reject) => {
        worker.on('completed', (_job, r) => resolveResult(r));
        worker.on('failed', (_job, err) => reject(err));
        producer
          .enqueueScan({ scanId, scanType: 'web-app-vuln', target: { url: `http://${targetIp}:8080/` } })
          .catch(reject);
      });
      // Result extraction still works alongside the streaming (DoD: T3.3 path intact).
      assert.equal(result.status, 'succeeded');

      // Give the last published events a moment to arrive on the subscriber.
      await new Promise((r) => setTimeout(r, 300));

      const lifecycles = events.filter((e) => e.type === 'lifecycle').map((e) => (e.type === 'lifecycle' ? e.status : ''));
      const phases = events.filter((e) => e.type === 'stage').map((e) => (e.type === 'stage' ? e.phase : ''));

      assert.ok(lifecycles.includes('RUNNING'), 'a RUNNING lifecycle event');
      assert.ok(lifecycles.includes('DONE'), 'a terminal DONE lifecycle event');
      assert.ok(phases.includes('web-load'), 'a web-load stage event');
      assert.ok(phases.includes('web-probes'), 'a web-probes stage event');
    } finally {
      await close();
      await worker.close();
      await producer.close();
      await cleanup.obliterate({ force: true });
      await cleanup.close();
    }
  });
});
