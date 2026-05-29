import { Worker } from 'bullmq';
import type { ConnectionOptions, Job } from 'bullmq';

import { SCAN_JOB_NAME, scanJobPayloadSchema, type ScanJobPayload } from '@anthrion/shared';

import { persistScanResult } from './persistence/persist-result';
import type { ScanResultStore } from './persistence/scan-repository';
import type { ScanProgressPublisher } from './progress/progress-publisher';
import { SCAN_QUEUE_NAME } from './queues';
import type { ScanSandbox } from './sandbox/manager';
import { executeScan, type ScanRunResult, type ScanRunSucceeded } from './scan-runner';
import type { ArtifactStore } from './storage/artifact-store';

/**
 * Scan job consumer (completed across Sprint 3): receive job → validate payload →
 * set RUNNING → run the scan-engine in a per-scan Docker sandbox (T3.2/T3.3) →
 * persist the result to Postgres + the transcript artifact to MinIO (T3.4).
 *
 * Status transitions (Part C): the worker drives RUNNING → DONE/FAILED. Creating the
 * QUEUED row is `api`'s job at `POST /scans` (T4.1); the worker transitions an
 * existing row.
 */

/** Everything the consumer needs, injected so the queue path is testable with stubs. */
export interface ScanProcessorDeps {
  sandbox: ScanSandbox;
  store: ScanResultStore;
  artifacts: ArtifactStore;
  progress: ScanProgressPublisher;
  /**
   * PDF report generation (T6.1). Wired in `main.ts` so every successful production scan
   * gets a report; injectable (and omittable) so execution/persistence tests stay focused.
   * It is best-effort by contract — it never throws and never affects the scan result.
   */
  generateReport?: (result: ScanRunSucceeded) => Promise<void>;
}

type ScanWorker = Worker<ScanJobPayload, ScanRunResult, typeof SCAN_JOB_NAME>;

/**
 * Process a single scan job: validate, mark RUNNING, run end-to-end, persist.
 *
 * Throwing vs returning (Part D): an invalid payload throws (queue trust boundary,
 * CLAUDE.md §3 → BullMQ records the failure); the sandbox manager throws on an
 * infrastructure failure (→ BullMQ retry). A scan-level failure (limit hit, engine
 * error, bad data) is persisted as a FAILED `Scan` with a reason — never silently as
 * "DONE with 0 findings".
 */
export async function processScanJob(
  job: Job<ScanJobPayload, ScanRunResult, typeof SCAN_JOB_NAME>,
  deps: ScanProcessorDeps,
): Promise<ScanRunResult> {
  // Validate the payload from the queue before using it (CLAUDE.md §3): job data is
  // JSON deserialized from Redis — an external trust boundary.
  const payload = scanJobPayloadSchema.parse(job.data);

  console.log(`[worker] scan job ${job.id} — scanId=${payload.scanId} type=${payload.scanType}`);

  // QUEUED → RUNNING at the start of execution (Part C.1). Publish the lifecycle event
  // so any connected SSE client sees the scan start (T4.2).
  await deps.store.markRunning(payload.scanId);
  await deps.progress.publishLifecycle(payload.scanId, 'RUNNING');

  // Stream the engine's stage events from the sandbox stdout straight to Redis (T4.2).
  const result = await executeScan(payload, deps.sandbox, {
    onEvent: (rawJson) => {
      void deps.progress.publishStage(payload.scanId, rawJson);
    },
  });

  // RUNNING → DONE/FAILED + findings + transcript artifact (Part C.2/C.3, Part B).
  await persistScanResult({ store: deps.store, artifacts: deps.artifacts }, result);

  // PDF security report (T6.1): eager, success states ONLY (DONE full or DONE partial),
  // AFTER findings are persisted. Best-effort by contract — `generateReport` never throws,
  // so a report failure cannot flip the scan or block the result. FAILED scans get no PDF.
  if (result.status === 'succeeded' && deps.generateReport !== undefined) {
    await deps.generateReport(result);
  }

  // Terminal lifecycle event so the SSE stream can complete (T4.2).
  await deps.progress.publishLifecycle(
    payload.scanId,
    result.status === 'succeeded' ? 'DONE' : 'FAILED',
    result.status === 'failed' ? `${result.reason}: ${result.message}` : undefined,
  );

  if (result.status === 'succeeded') {
    console.log(
      `[worker] scan ${result.scanId} DONE — ${result.findings.length} finding(s), ${result.report.scanType} (${result.durationMs}ms)`,
    );
  } else {
    console.error(`[worker] scan ${result.scanId} FAILED (${result.reason}) — ${result.message}`);
  }

  return result;
}

/**
 * Create and start a BullMQ worker that consumes scan jobs.
 *
 * @param connection - ioredis connection or options (Workers need `maxRetriesPerRequest: null`).
 * @param queueName - defaults to {@link SCAN_QUEUE_NAME}; override only for test isolation.
 * @param deps - sandbox + persistence dependencies (injectable for tests).
 */
export function createScanWorker(
  connection: ConnectionOptions,
  queueName: string = SCAN_QUEUE_NAME,
  deps: ScanProcessorDeps,
): ScanWorker {
  return new Worker<ScanJobPayload, ScanRunResult, typeof SCAN_JOB_NAME>(
    queueName,
    (job) => processScanJob(job, deps),
    { connection },
  );
}
