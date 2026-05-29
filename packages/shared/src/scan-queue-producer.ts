import { Queue } from 'bullmq';
import type { ConnectionOptions, Job } from 'bullmq';

import {
  DEFAULT_SCAN_JOB_OPTIONS,
  SCAN_JOB_NAME,
  SCAN_QUEUE_NAME,
  parseScanJobPayload,
  type ScanJobPayload,
} from './scan-job';

/** Result type of a scan job. Filled in T3.3/T3.4 (Finding summary); `void` for now. */
type ScanJobResult = void;

type ScanQueue = Queue<ScanJobPayload, ScanJobResult, typeof SCAN_JOB_NAME>;

/**
 * Producer for the BullMQ scan queue (T3.1). Used by `apps/api` to enqueue scan
 * jobs (full wiring into `POST /scans` is T4.1).
 *
 * Lives in `packages/shared` so both `api` (producer) and the queue contract stay
 * in one place without `apps/*` importing each other (`ARCHITECTURE.md` §2). The
 * Redis connection is INJECTED by the caller — this module opens no connection at
 * import time, so importing `shared` stays side-effect-free (important: `web` also
 * imports `shared`). The caller owns the connection lifecycle and calls `close()`.
 */
export class ScanQueueProducer {
  private readonly queue: ScanQueue;

  /**
   * @param connection - ioredis connection or options (BullMQ `ConnectionOptions`).
   * @param queueName - defaults to {@link SCAN_QUEUE_NAME}; override only for test
   *   isolation. Production always uses the single canonical scan queue.
   */
  constructor(connection: ConnectionOptions, queueName: string = SCAN_QUEUE_NAME) {
    this.queue = new Queue(queueName, { connection });
  }

  /**
   * Validate `input` with the Zod payload schema, then enqueue it. Validation
   * happens BEFORE the job enters the queue (`CLAUDE.md` §3): unvalidated data is
   * never enqueued. Throws `ZodError` on an invalid payload (nothing is enqueued).
   */
  async enqueueScan(input: unknown): Promise<Job<ScanJobPayload, ScanJobResult, typeof SCAN_JOB_NAME>> {
    const payload = parseScanJobPayload(input);
    return this.queue.add(SCAN_JOB_NAME, payload, DEFAULT_SCAN_JOB_OPTIONS);
  }

  /** Close the underlying queue connection. Call on app shutdown. */
  async close(): Promise<void> {
    await this.queue.close();
  }
}
