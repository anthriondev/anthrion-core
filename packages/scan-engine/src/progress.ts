import { z } from 'zod';

/**
 * Scan progress events (T4.2). The engine emits STAGE-level events (not per-probe —
 * too noisy, Context §1) via an optional `onProgress` callback at phase boundaries.
 *
 * The engine stays PURE (ARCHITECTURE.md §2): a callback is just a function — the
 * engine knows nothing about SSE/Redis/stdout. `sandbox-runtime` provides a callback
 * that serialises these to the container's stdout (T4.2 §3); the worker turns them
 * into the cross-app SSE wire event (`@anthrion/shared` `scanStreamEvent`).
 *
 * This type lives in `scan-engine` (the emitter owns it; the phases ARE engine
 * concepts) and is pure wire data — only strings/numbers, no HTTP/DB.
 */

/** The phases a scan moves through, derived from the real engine structure. */
export const scanProgressPhaseSchema = z.enum([
  'layer-1', // AI scan — Layer 1 static probes
  'layer-2', // AI scan — Layer 2 adaptive attacker
  'layer-2-category', // AI scan — Layer 2 attacking one category
  'web-load', // Web scan — page load
  'web-probes', // Web scan — DAST probes
  'api-scan', // API scan — Phase 1.5 Sprint A1
  'web3-l1', // Web3 dApp scan — Layer 1 wallet interaction (Phase 1.5 Sprint A3)
  'web3-l3', // Web3 dApp scan — Layer 3 on-chain context (Phase 1.5 Sprint A3, T-A3.5)
  'web3-l2', // Web3 dApp scan — Layer 2 frontend/infrastructure (Phase 1.5 Sprint A3, T-A3.6)
]);

export type ScanProgressPhase = z.infer<typeof scanProgressPhaseSchema>;

export const scanProgressStatusSchema = z.enum(['started', 'completed']);

export type ScanProgressStatus = z.infer<typeof scanProgressStatusSchema>;

/**
 * A single stage event. `detail` carries small, UI-friendly extras (e.g. a category
 * name, a finding count) as primitives — never findings themselves (those are the
 * scan result, not progress).
 */
export const scanProgressEventSchema = z.object({
  phase: scanProgressPhaseSchema,
  status: scanProgressStatusSchema,
  /** Human-readable one-liner for the UI (e.g. "Layer 1 complete: 3 finding(s)"). */
  message: z.string(),
  detail: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
});

export type ScanProgressEvent = z.infer<typeof scanProgressEventSchema>;

/** Optional progress sink passed into the engine. Engine-pure: just a function. */
export type ScanProgressCallback = (event: ScanProgressEvent) => void;

/**
 * Invoke a progress callback defensively. Progress is best-effort and runs ALONGSIDE
 * the scan (Context §2) — a misbehaving callback must NEVER alter scan behaviour or
 * results, so its errors are contained here and not propagated into the engine.
 */
export function emitProgress(onProgress: ScanProgressCallback | undefined, event: ScanProgressEvent): void {
  if (onProgress === undefined) {
    return;
  }
  try {
    onProgress(event);
  } catch {
    // Best-effort: a failing progress sink must not affect the scan (Context §2).
  }
}
