import { z } from 'zod';

/**
 * Scan progress STREAM contract (T4.2) — the cross-app SSE/Redis wire event.
 *
 * Path (ARCHITECTURE.md §7): worker publishes these to Redis pub/sub →
 * `api` relays them over SSE (`GET /scans/:id/stream`) → `web` renders them.
 *
 * Lives in `shared` (not `scan-engine`) because it is the cross-app wire contract used
 * by `api`/`web`/`worker` — and `api`/`web` must NOT depend on `scan-engine` (it pulls
 * Playwright). Like `ScanJobPayload` (T3.1), it is PRIMITIVE WIRE DATA defined here
 * independently; the worker maps the engine's `ScanProgressEvent` (scan-engine, the
 * emitter's own type) onto the `stage` variant below. The phase strings mirror the
 * engine's phases as wire data — kept in sync by the worker mapping + tests.
 */

/** Redis pub/sub channel a scan's progress events are published on (per scan). */
export function scanProgressChannel(scanId: string): string {
  return `scan-progress:${scanId}`;
}

/** Engine stage phases (mirrors scan-engine's `ScanProgressPhase` as wire data). */
const stagePhaseSchema = z.enum([
  'layer-1',
  'layer-2',
  'layer-2-category',
  'web-load',
  'web-probes',
  'api-scan',
  'web3-l1',
  'web3-l3',
  'web3-l2',
]);

/** A stage-level engine progress event, forwarded by the worker. */
const stageStreamEventSchema = z.object({
  type: z.literal('stage'),
  phase: stagePhaseSchema,
  status: z.enum(['started', 'completed']),
  message: z.string(),
  detail: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
});

/** A scan lifecycle/status event, emitted by the worker (and as an api snapshot). */
const lifecycleStreamEventSchema = z.object({
  type: z.literal('lifecycle'),
  status: z.enum(['QUEUED', 'RUNNING', 'DONE', 'FAILED']),
  message: z.string().optional(),
});

/** The event the client receives over SSE — discriminated on `type`. */
export const scanStreamEventSchema = z.discriminatedUnion('type', [
  stageStreamEventSchema,
  lifecycleStreamEventSchema,
]);

export type ScanStreamEvent = z.infer<typeof scanStreamEventSchema>;
export type ScanStreamStageEvent = z.infer<typeof stageStreamEventSchema>;
export type ScanStreamLifecycleEvent = z.infer<typeof lifecycleStreamEventSchema>;

/**
 * Parse + validate a scan stream event from an untrusted JSON string (a Redis pub/sub
 * message). Returns the validated event, or `undefined` if it is not a valid event —
 * callers skip invalid messages rather than forwarding garbage (CLAUDE.md §3).
 */
export function parseScanStreamEvent(raw: string): ScanStreamEvent | undefined {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return undefined;
  }
  const parsed = scanStreamEventSchema.safeParse(json);
  return parsed.success ? parsed.data : undefined;
}
