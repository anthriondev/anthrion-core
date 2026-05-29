import IORedis from 'ioredis';

import { createPrismaClient } from '@anthrion/db';
import { env } from '@anthrion/shared';

import { ScanRepository } from './persistence/scan-repository';
import { RedisScanProgressPublisher } from './progress/progress-publisher';
import { SCAN_QUEUE_NAME } from './queues';
import { generateScanReport } from './report/generate-report';
import { SandboxSchemaDriftError, verifySandboxImageMatchesSource } from './sandbox/drift-guard';
import { DockerSandboxManager } from './sandbox/manager';
import { createScanWorker } from './scan-consumer';
import { MinioArtifactStore } from './storage/artifact-store';

// Default matches docker-compose (Redis published on 6380, docker-compose.yml / .env).
const REDIS_URL = process.env['REDIS_URL'] ?? 'redis://localhost:6380';

// A Worker uses blocking Redis commands, so `maxRetriesPerRequest: null` is required.
const connection = new IORedis(REDIS_URL, {
  maxRetriesPerRequest: null,
});

connection.on('connect', () => {
  console.log('[worker] Redis connected');
});

connection.on('error', (err: Error) => {
  console.error('[worker] Redis error:', err.message);
});

// Persistence (T3.4): one Prisma client + one MinIO artifact store for the worker's
// lifetime. The bucket is ensured before accepting jobs.
const prisma = createPrismaClient(env.DATABASE_URL);
const artifacts = new MinioArtifactStore();
const store = new ScanRepository(prisma);

// Progress publishing (T4.2): a SEPARATE Redis connection for pub/sub `publish` — kept
// off the BullMQ Worker connection, which is reserved for blocking queue commands.
const progressConnection = new IORedis(REDIS_URL);
const progress = new RedisScanProgressPublisher(progressConnection);

artifacts
  .ensureBucket()
  .then(() => console.log(`[worker] MinIO bucket ready: ${env.MINIO_BUCKET}`))
  .catch((err: unknown) => {
    console.error('[worker] MinIO bucket setup failed:', err instanceof Error ? err.message : String(err));
  });

// One sandbox manager for the worker's lifetime. Sweep any containers left over from
// a previous crash before accepting jobs (T3.2 crash recovery — never accumulate).
const sandbox = new DockerSandboxManager();
sandbox
  .sweepOrphans()
  .then((removed) => {
    if (removed > 0) {
      console.log(`[worker] swept ${removed} orphaned sandbox container(s) on startup`);
    }
  })
  .catch((err: unknown) => {
    console.error('[worker] orphan sweep failed:', err instanceof Error ? err.message : String(err));
  });

// T-FIX.9: refuse to accept jobs when the running sandbox IMAGE was built against
// a different scan-engine commit than this worker (the "2-element scanTypeSchema"
// incident). Hard guard: failure here exits 1 so the orchestrator restarts and a
// stale image cannot silently fail the first live scan.
verifySandboxImageMatchesSource(sandbox)
  .then(() => {
    console.log('[worker] sandbox image schema OK');
  })
  .catch((err: unknown) => {
    if (err instanceof SandboxSchemaDriftError) {
      console.error(`[worker] ${err.message}`);
    } else {
      console.error('[worker] sandbox image verification failed:', err instanceof Error ? err.message : String(err));
    }
    process.exit(1);
  });

const worker = createScanWorker(connection, SCAN_QUEUE_NAME, {
  sandbox,
  store,
  artifacts,
  progress,
  // PDF security report (T6.1): generated for every successful scan. `store` (ScanRepository)
  // provides the report metadata + artifact recording; the renderer launches the worker's
  // Chromium per report (same Chromium the web scan uses). Best-effort — see generateScanReport.
  generateReport: (result) => generateScanReport({ store, artifacts }, result).then(() => undefined),
});

worker.on('completed', (job) => {
  console.log(`[worker] job ${job.id} completed`);
});

worker.on('failed', (job, err) => {
  console.error(`[worker] job ${job?.id} failed:`, err.message);
});

console.log(`[worker] listening on queue: ${SCAN_QUEUE_NAME}`);
