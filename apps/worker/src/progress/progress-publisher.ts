import type IORedis from 'ioredis';

import { scanProgressEventSchema } from '@anthrion/scan-engine';
import { scanProgressChannel, scanStreamEventSchema, type ScanStreamEvent } from '@anthrion/shared';

/**
 * Publishes scan progress to Redis pub/sub (T4.2, Part B). The worker is the bridge to
 * Redis (ARCHITECTURE.md §7) — the sandbox container never touches Redis (T3.2 isolation
 * stays intact); events leave the container only via stdout, and the worker forwards
 * them here.
 */

export type ScanLifecycleStatus = 'QUEUED' | 'RUNNING' | 'DONE' | 'FAILED';

/** Publisher surface (interface → stubbable in unit tests). */
export interface ScanProgressPublisher {
  /** Forward one raw engine progress-event line (from container stdout) to Redis. */
  publishStage(scanId: string, rawEngineEvent: string): Promise<void>;
  /** Publish a scan lifecycle/status event to Redis. */
  publishLifecycle(scanId: string, status: ScanLifecycleStatus, message?: string): Promise<void>;
}

export class RedisScanProgressPublisher implements ScanProgressPublisher {
  constructor(private readonly redis: IORedis) {}

  async publishStage(scanId: string, rawEngineEvent: string): Promise<void> {
    // The event came from the container's stdout — UNTRUSTED. Validate against the
    // engine schema before mapping/publishing (CLAUDE.md §3); skip anything invalid.
    let json: unknown;
    try {
      json = JSON.parse(rawEngineEvent);
    } catch {
      return; // not JSON — not a real event line; drop it
    }
    const parsed = scanProgressEventSchema.safeParse(json);
    if (!parsed.success) {
      console.warn(`[worker] dropping invalid progress event for scan ${scanId}`);
      return;
    }
    const event = parsed.data;
    await this.publish(scanId, {
      type: 'stage',
      phase: event.phase,
      status: event.status,
      message: event.message,
      ...(event.detail !== undefined ? { detail: event.detail } : {}),
    });
  }

  async publishLifecycle(scanId: string, status: ScanLifecycleStatus, message?: string): Promise<void> {
    await this.publish(scanId, {
      type: 'lifecycle',
      status,
      ...(message !== undefined ? { message } : {}),
    });
  }

  private async publish(scanId: string, event: ScanStreamEvent): Promise<void> {
    // Validate our own wire event before publishing — a contract drift fails loudly here.
    const valid = scanStreamEventSchema.parse(event);
    await this.redis.publish(scanProgressChannel(scanId), JSON.stringify(valid));
  }
}
