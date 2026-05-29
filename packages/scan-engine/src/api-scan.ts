import type { OwaspApiCategory } from './category';
import { findingSchema, type Evidence, type Finding } from './finding';
import { emitProgress, type ScanProgressCallback } from './progress';
import { API_PROBES } from './api-probes';
import { ApiTargetAdapterError, type ApiCoverageMode, type ApiTarget } from './api-target';
import type { ApiDetection, ApiProbe } from './api-probe';

/**
 * API security scan runner (Phase 1.5 Sprint A1, T-A1.2).
 *
 * Drives the curated `API_PROBES` against an `ApiTarget` and produces a
 * normalised `ApiScanReport`. The runner is target-agnostic: works on a raw
 * target (single endpoint, `coverage = 'raw'`) AND a spec target (all
 * operations, `coverage = 'spec'`). Probes never branch on mode; the report
 * carries `coverage` so the report layer (T-A1.4) can honestly surface the
 * "we tested 1 of N possible endpoints" caveat for raw mode.
 *
 * Honesty rules (same family as `WEB_PROBES` runner):
 *  - A probe that times out is `not-executed`, never `clean`.
 *  - A probe that throws an unexpected error is `not-executed`, captured as
 *    an error message, NEVER silently swallowed into "safe".
 *  - If the baseline reachability check fails (every adapter request raises
 *    `ApiTargetAdapterError` for one round-trip), every probe is
 *    `not-executed` and outcome is `target-unreachable` — NOT a clean bill.
 *  - Coverage breadth is surfaced via `coverage` and `endpointCount` so the
 *    report layer is responsible for showing raw-mode shallowness honestly.
 *
 * Each `Finding` is Zod-validated before leaving the engine (ARCHITECTURE.md §4.4).
 */

export type ApiProbeStatus = 'detected' | 'clean' | 'not-executed';

export interface ApiProbeResult {
  probeId: string;
  technique: string;
  category: OwaspApiCategory;
  status: ApiProbeStatus;
  /** Explanation of the decision, or the reason the probe did not execute. */
  rationale: string;
  /** Normalised findings — present iff `status === 'detected'`. */
  findings: Finding[];
  /** Error / timeout message — present iff `status === 'not-executed'`. */
  error?: string;
}

/**
 * Summary outcome of an API scan:
 *  - `vulnerable`         — ≥1 probe detected an issue.
 *  - `passed`             — all probes executed, zero findings.
 *  - `passed-with-gaps`   — no findings, but ≥1 probe did not execute. Coverage
 *                           is incomplete → NOT a clean bill.
 *  - `target-unreachable` — the baseline request did not yield any response;
 *                           no probe meaningfully ran. NOT "safe".
 */
export type ApiScanOutcome = 'vulnerable' | 'passed' | 'passed-with-gaps' | 'target-unreachable';

export interface ApiScanStats {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
}

export interface ApiScanReport {
  /** Coverage breadth of the target — propagates from `ApiTarget.coverage`. */
  coverage: ApiCoverageMode;
  /** Number of endpoints the target enumerated. */
  endpointCount: number;
  outcome: ApiScanOutcome;
  findings: Finding[];
  results: ApiProbeResult[];
  stats: ApiScanStats;
}

export interface RunApiScanOptions {
  /** Per-probe timeout (ms). A probe whose own logic hangs is cut. */
  probeTimeoutMs?: number;
  /** Override the curated probe set. */
  probes?: readonly ApiProbe[];
  /**
   * Per-probe endpoint sampling ceiling. A spec target with hundreds of
   * operations × an N-burst probe (e.g. `api:no-rate-limit` with 5 requests
   * per endpoint) can produce thousands of requests, which is a real risk to
   * the target and to the scan budget. When the target's endpoint count
   * exceeds this ceiling, only the first `maxEndpointsPerProbe` are sampled
   * — surfaced via report progress so the user sees coverage is bounded.
   * Default is generous (100) so realistic specs run unimpeded; the worker
   * (T-A1.3) can pass a tighter value.
   *
   * Probes that are target-level (e.g. `api:docs-exposed`) are unaffected —
   * they don't iterate endpoints.
   */
  maxEndpointsPerProbe?: number;
  /** Stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

/**
 * Per-probe timeout, ms. A probe iterates endpoints and round-trips for each;
 * the adapter's own per-request timeout caps each request, but the probe
 * itself (e.g. `noRateLimitProbe`'s 5-request burst across N endpoints) needs a
 * higher per-probe ceiling. 90s comfortably accommodates 10 endpoints × 30s
 * per-request worst case for the slowest probe while still being a real cap
 * for a probe whose logic hangs.
 */
export const DEFAULT_API_PROBE_TIMEOUT_MS = 90_000;

/**
 * Default endpoint sampling ceiling per probe. Realistic specs sit well below
 * this; a spec with > 100 operations gets sampled. The worker (T-A1.3) is
 * responsible for passing a tighter ceiling when scan budgets demand it.
 */
export const DEFAULT_API_MAX_ENDPOINTS_PER_PROBE = 100;

class ProbeTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProbeTimeoutError';
  }
}

function withTimeout<T>(ms: number, label: string, op: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new ProbeTimeoutError(`${label}: timed out after ${ms}ms`)),
      ms,
    );
    op.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

/**
 * Run the curated `API_PROBES` (or `options.probes`) against `target`.
 *
 * Behavior:
 *  1. Baseline reachability check — one request to the first endpoint. If it
 *     raises `ApiTargetAdapterError`, the target is unreachable: every probe
 *     is marked `not-executed`, outcome is `target-unreachable`. Any other
 *     baseline response (including 4xx/5xx) means the target IS reachable;
 *     probes proceed.
 *  2. Each probe runs under a per-probe timeout. Detections are converted to
 *     Zod-validated `Finding`s with the probe's metadata.
 */
export async function runApiScan(
  target: ApiTarget,
  options: RunApiScanOptions = {},
): Promise<ApiScanReport> {
  const probes = options.probes ?? API_PROBES;
  const probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_API_PROBE_TIMEOUT_MS;
  const maxEndpointsPerProbe = options.maxEndpointsPerProbe ?? DEFAULT_API_MAX_ENDPOINTS_PER_PROBE;
  const onProgress = options.onProgress;
  const coverage = target.coverage;
  const totalEndpoints = target.endpoints().length;
  const sampled = totalEndpoints > maxEndpointsPerProbe;
  const probeTarget = sampled ? capEndpoints(target, maxEndpointsPerProbe) : target;
  const sampledEndpointCount = probeTarget.endpoints().length;

  emitProgress(onProgress, {
    phase: 'api-scan',
    status: 'started',
    message: sampled
      ? `API scan started (${probes.length} probes, ${sampledEndpointCount} of ${totalEndpoints} endpoints sampled, coverage=${coverage})`
      : `API scan started (${probes.length} probe${probes.length === 1 ? '' : 's'}, ${totalEndpoints} endpoint${totalEndpoints === 1 ? '' : 's'}, coverage=${coverage})`,
    detail: {
      probes: probes.length,
      endpoints: totalEndpoints,
      sampledEndpoints: sampledEndpointCount,
      coverage,
    },
  });

  // ── 1. Baseline reachability ────────────────────────────────────────────
  const reachability = await baselineReachable(target);
  if (!reachability.reachable) {
    const notExecutedResults = probes.map((probe) =>
      buildNotExecutedResult(probe, `target unreachable: ${reachability.reason}`),
    );
    emitProgress(onProgress, {
      phase: 'api-scan',
      status: 'completed',
      message: 'API scan: target unreachable — every probe not-executed (honest, not "safe")',
      detail: { outcome: 'target-unreachable', reason: reachability.reason },
    });
    return {
      coverage,
      endpointCount: totalEndpoints,
      outcome: 'target-unreachable',
      findings: [],
      results: notExecutedResults,
      stats: {
        total: probes.length,
        executed: 0,
        detected: 0,
        clean: 0,
        notExecuted: probes.length,
      },
    };
  }

  // ── 2. Run probes ───────────────────────────────────────────────────────
  const results: ApiProbeResult[] = [];
  const findings: Finding[] = [];
  for (const probe of probes) {
    let detections: readonly ApiDetection[];
    try {
      detections = await withTimeout(
        probeTimeoutMs,
        probe.id,
        probe.evaluate(probeTarget),
      );
    } catch (cause) {
      const message =
        cause instanceof Error
          ? cause.message
          : `probe failed: ${String(cause)}`;
      results.push(buildNotExecutedResult(probe, message));
      continue;
    }

    if (detections.length === 0) {
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'clean',
        rationale: `${probe.technique} did not detect ${probe.category} on this target.`,
        findings: [],
      });
      continue;
    }

    const probeFindings: Finding[] = [];
    for (let i = 0; i < detections.length; i++) {
      const detection = detections[i];
      if (detection === undefined) continue;
      const finding = detectionToFinding(probe, detection, i);
      probeFindings.push(finding);
      findings.push(finding);
    }
    results.push({
      probeId: probe.id,
      technique: probe.technique,
      category: probe.category,
      status: 'detected',
      rationale:
        probeFindings.length === 1
          ? (detections[0]?.rationale ?? probe.description)
          : `${probe.technique} produced ${probeFindings.length} findings on this target.`,
      findings: probeFindings,
    });
  }

  // ── 3. Outcome ──────────────────────────────────────────────────────────
  const stats: ApiScanStats = {
    total: results.length,
    executed: results.filter((r) => r.status !== 'not-executed').length,
    detected: results.filter((r) => r.status === 'detected').length,
    clean: results.filter((r) => r.status === 'clean').length,
    notExecuted: results.filter((r) => r.status === 'not-executed').length,
  };

  const outcome: ApiScanOutcome =
    stats.detected > 0 ? 'vulnerable' : stats.notExecuted > 0 ? 'passed-with-gaps' : 'passed';

  emitProgress(onProgress, {
    phase: 'api-scan',
    status: 'completed',
    message: `API scan: ${outcome} (${stats.detected} detected / ${stats.clean} clean / ${stats.notExecuted} not-executed)`,
    detail: {
      outcome,
      detected: stats.detected,
      clean: stats.clean,
      notExecuted: stats.notExecuted,
      findings: findings.length,
    },
  });

  return {
    coverage,
    endpointCount: totalEndpoints,
    outcome,
    findings,
    results,
    stats,
  };
}

/**
 * Wrap a target so `endpoints()` returns at most `max` entries. The wrapper
 * shares `baseUrl`, `coverage`, and `request` with the underlying target —
 * origin lock and per-request mechanics are unchanged. Used by the runner to
 * enforce a per-probe endpoint sampling ceiling without making probes
 * budget-aware.
 */
function capEndpoints(target: ApiTarget, max: number): ApiTarget {
  const capped = target.endpoints().slice(0, max);
  return {
    baseUrl: target.baseUrl,
    coverage: target.coverage,
    endpoints: () => capped,
    request: target.request.bind(target),
  };
}

interface ReachabilityResult {
  reachable: boolean;
  reason: string;
}

async function baselineReachable(target: ApiTarget): Promise<ReachabilityResult> {
  const [firstEndpoint] = target.endpoints();
  if (firstEndpoint === undefined) {
    return { reachable: false, reason: 'target enumerates no endpoints' };
  }
  try {
    await target.request({
      endpoint: firstEndpoint,
      url: `${target.baseUrl}${firstEndpoint.pathTemplate.replace(/\{[^}]+\}/g, 'baseline')}`,
      method: firstEndpoint.method,
    });
    return { reachable: true, reason: '' };
  } catch (cause) {
    if (cause instanceof ApiTargetAdapterError) {
      return { reachable: false, reason: cause.message };
    }
    // Unexpected error — propagate as if reachable so probes can surface
    // individual failures honestly; the runner's reachability check is a
    // baseline-only heuristic.
    return { reachable: true, reason: '' };
  }
}

function buildNotExecutedResult(probe: ApiProbe, error: string): ApiProbeResult {
  return {
    probeId: probe.id,
    technique: probe.technique,
    category: probe.category,
    status: 'not-executed',
    rationale: `Probe ${probe.id} did not execute: ${error}`,
    findings: [],
    error,
  };
}

function detectionToFinding(probe: ApiProbe, detection: ApiDetection, index: number): Finding {
  const evidence: Evidence = {
    input: `${probe.technique} against ${
      detection.endpoint !== undefined
        ? `${detection.endpoint.method} ${detection.endpoint.pathTemplate}`
        : 'target origin'
    }`,
    output: detection.evidence,
    ...(detection.metadata !== undefined ? { metadata: detection.metadata } : {}),
  };

  const id = detection.endpoint !== undefined
    ? `${probe.id}#${detection.endpoint.method}:${detection.endpoint.pathTemplate}`
    : `${probe.id}#${index}`;

  return findingSchema.parse({
    id,
    severity: detection.severity ?? probe.severity,
    category: probe.category,
    title: probe.title,
    description: detection.description ?? probe.description,
    evidence,
    recommendation: probe.recommendation,
  });
}
