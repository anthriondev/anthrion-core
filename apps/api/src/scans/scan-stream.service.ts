import { Injectable, Logger, type MessageEvent } from '@nestjs/common';
import IORedis from 'ioredis';
import { Observable } from 'rxjs';

import type { ScanStatus } from '@anthrion/db';
import { parseScanStreamEvent, scanProgressChannel, type ScanStreamEvent, env } from '@anthrion/shared';

/**
 * Server-Sent Events relay for scan progress (T4.2, Part C). `api` only RELAYS
 * (ARCHITECTURE.md §3/§7): it subscribes to the worker's Redis pub/sub channel for one
 * scan and forwards each event to the connected client via NestJS `@Sse` (which owns the
 * SSE wire protocol + flushing). It never runs a scan.
 *
 * Lifecycle: one dedicated Redis subscriber connection per stream, torn down when the
 * Observable is unsubscribed — i.e. on client disconnect or when a terminal lifecycle
 * event completes the stream. No dangling subscriptions.
 */
@Injectable()
export class ScanStreamService {
  private readonly logger = new Logger(ScanStreamService.name);
  /** Live stream count — used by tests to assert subscriptions are cleaned up. */
  private active = 0;

  get activeStreams(): number {
    return this.active;
  }

  /**
   * Build the SSE event stream for one scan. `getStatus` is the owner-scoped current
   * status (already authorized by the guard); it seeds the snapshot and is re-checked
   * right after subscribing to close the race where the scan finishes between the auth
   * check and the subscribe (otherwise the stream could hang).
   */
  observe(scanId: string, getStatus: () => Promise<ScanStatus>): Observable<MessageEvent> {
    return new Observable<MessageEvent>((subscriber) => {
      this.active += 1;
      let redis: IORedis | undefined;
      let closed = false;

      const cleanup = (): void => {
        if (closed) {
          return;
        }
        closed = true;
        this.active -= 1;
        if (redis !== undefined) {
          void redis.quit().catch(() => undefined);
        }
      };

      const emit = (event: ScanStreamEvent): void => subscriber.next({ data: event });

      void (async () => {
        // Snapshot: where the scan is right now (so a late client is not left blank).
        const status = await getStatus();
        emit({ type: 'lifecycle', status });
        if (isTerminal(status)) {
          subscriber.complete(); // already finished → close immediately, do not hang
          return;
        }

        redis = new IORedis(env.REDIS_URL);
        redis.on('message', (_channel, message) => {
          const event = parseScanStreamEvent(message);
          if (event === undefined) {
            return; // ignore anything that is not a valid event (CLAUDE.md §3)
          }
          emit(event);
          if (event.type === 'lifecycle' && isTerminal(event.status)) {
            subscriber.complete(); // terminal → complete the stream
          }
        });
        await redis.subscribe(scanProgressChannel(scanId));

        // Race-closer: the scan may have finished between the auth check and the subscribe.
        // A status-fetch failure here is non-fatal (the stream continues via subscribed
        // events), but it must be observable — log it rather than swallowing (CLAUDE.md §3).
        const current = await getStatus().catch((error: unknown) => {
          this.logger.warn(`SSE race-closer status check failed for scan ${scanId}: ${describe(error)}`);
          return undefined;
        });
        if (current !== undefined && isTerminal(current)) {
          emit({ type: 'lifecycle', status: current });
          subscriber.complete();
        }
      })().catch((error: unknown) => {
        this.logger.error(`SSE stream failed for scan ${scanId}: ${describe(error)}`);
        subscriber.error(error);
      });

      // Teardown runs on unsubscribe (client disconnect) AND on complete — no leaks.
      return cleanup;
    });
  }
}

function isTerminal(status: ScanStatus): boolean {
  return status === 'DONE' || status === 'FAILED';
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
