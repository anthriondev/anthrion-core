import { z } from 'zod';

import type { OwaspApiCategory } from './category';
import type { Severity } from './severity';
import { ApiTargetAdapterError, type ApiEndpoint, type ApiTarget } from './api-target';

/**
 * API security scan — probe abstraction (Phase 1.5 Sprint A1, T-A1.2).
 *
 * An `ApiProbe` is the API equivalent of the web scan's `WebProbe` and the AI
 * scan's `StaticProbe`: a rule-based, LLM-free check that drives an
 * `ApiTarget` (raw or spec mode — the probe never branches on mode) and
 * decides, with an explainable rationale, whether the target exhibits the
 * vulnerability.
 *
 * Each probe runs against the whole target — not a single endpoint. Some
 * checks are per-endpoint (the probe iterates `target.endpoints()`) and emit
 * a detection per endpoint they flag; others are target-level (one detection
 * for the whole target). This matches the OWASP API Top 10 mix: BOLA/BFLA-style
 * checks are per-endpoint, security-misconfig and improper-inventory checks
 * are typically target-level.
 *
 * Probes are async because they round-trip to the live target. The per-scan
 * timeout (carried by the adapter) bounds each individual request; the runner
 * (`api-scan.ts`, T-A1.2 continued) ALSO wraps each probe in a per-probe
 * timeout so a probe whose own logic hangs is cut and reported `not-executed`
 * — never "safe".
 */

/** Outcome of one probe against the target. */
export interface ApiDetection {
  /**
   * The endpoint that triggered detection — present iff the probe is
   * per-endpoint and a specific endpoint is implicated. Target-level probes
   * (security-misconfig at origin, improper-inventory) leave it absent.
   */
  endpoint?: ApiEndpoint;
  /** Explanation of the decision (positive). ALWAYS populated. */
  rationale: string;
  /** Observed value/values that triggered detection — becomes evidence. */
  evidence: string;
  /** Optional extra metadata for the Finding evidence. */
  metadata?: Record<string, string>;
  /**
   * Optional severity override for context-dependent findings (e.g.
   * permissive CORS WITH credentials is worse than without). Falls back to
   * `probe.severity` when absent.
   */
  severity?: Severity;
  /**
   * Optional description override when the same probe id has materially
   * different failure modes (e.g. T-FIX.6: permissive CORS — wildcard alone is a
   * different concern from wildcard + credentials). Falls back to
   * `probe.description` when absent.
   */
  description?: string;
}

/** A single API security probe. */
export interface ApiProbe {
  /** Stable, unique probe id (prefix `api:` keeps it distinct from web/AI ids). */
  id: string;
  /** Short technique label for documentation and evidence. */
  technique: string;
  /** OWASP API category of the Finding produced by this probe. */
  category: OwaspApiCategory;
  /** Default severity if the probe triggers (may be overridden per detection). */
  severity: Severity;
  /** Concise Finding title. */
  title: string;
  /** Description of the vulnerability being tested. */
  description: string;
  /** Basic mitigation recommendation. */
  recommendation: string;
  /**
   * Run the probe against the target. Returns 0..N detections.
   * MUST NOT throw under normal "I checked and didn't find anything" — return
   * an empty array. THROW only for genuine probe-internal failure (the runner
   * marks the probe `not-executed` in that case, never "safe").
   * `ApiTargetAdapterError`s raised by individual requests are non-fatal at the
   * probe level: a probe that does N requests can catch and continue.
   */
  evaluate(target: ApiTarget): Promise<ApiDetection[]>;
}

/** Convenience: build an empty-detections result with no allocation. */
export const NO_DETECTIONS: readonly ApiDetection[] = Object.freeze([]);

/**
 * Build a fully-qualified URL for hitting an endpoint on the target.
 *
 * Concatenates `target.baseUrl` + `endpoint.pathTemplate` (which already
 * carries the spec's basePath, if any — see `api-spec-adapter.ts:extractEndpoints`).
 * Substitutes path variables in `{name}` form using `pathParams`. Each value
 * is `encodeURIComponent`-encoded — slashes and dots in user-provided values
 * are encoded so a path-param value cannot break out of its slot.
 *
 * This helper exists so probes never reinvent URL construction and accidentally
 * land traffic on the wrong path within the same origin. The adapter's
 * origin lock catches different-origin attempts; this helper keeps same-origin
 * URLs well-formed.
 *
 * Limitation (honest): this helper does NOT support testing path-traversal
 * attacks. A probe that needs to send `/files/../admin` to the server cannot
 * use this helper — WHATWG URL normalises dot-segments (`new URL("/a/../b")` →
 * `/b`), so any traversal sequence is collapsed by the time fetch runs. Such
 * probes (when they arrive in a later sprint) will need a different
 * URL-construction path that bypasses URL normalisation while still
 * respecting the adapter origin lock.
 */
export function buildEndpointUrl(
  target: ApiTarget,
  endpoint: ApiEndpoint,
  options: {
    pathParams?: Record<string, string>;
    query?: Record<string, string>;
  } = {},
): string {
  let path = endpoint.pathTemplate;
  if (options.pathParams !== undefined) {
    for (const [name, value] of Object.entries(options.pathParams)) {
      path = path.replaceAll(`{${name}}`, encodeURIComponent(value));
    }
  }
  const url = new URL(target.baseUrl);
  // Avoid `new URL(path, base)` because if `path` starts with `/`, it replaces
  // the basePath baked into `pathTemplate`. We instead set pathname directly.
  url.pathname = path;
  if (options.query !== undefined) {
    for (const [name, value] of Object.entries(options.query)) {
      url.searchParams.set(name, value);
    }
  }
  return url.toString();
}

/**
 * Run a single HTTP request, swallowing `ApiTargetAdapterError` into a normal
 * result so probes can iterate many endpoints without one failure aborting
 * the whole probe. Adapter errors are captured in the result so the probe can
 * inspect them if needed.
 */
export interface RequestOutcome {
  ok: boolean;
  status?: number;
  headers?: Readonly<Record<string, string>>;
  body?: string;
  bodyTruncated?: boolean;
  error?: ApiTargetAdapterError;
}

export async function tryRequest(
  target: ApiTarget,
  req: Parameters<ApiTarget['request']>[0],
): Promise<RequestOutcome> {
  try {
    const response = await target.request(req);
    return {
      ok: true,
      status: response.status,
      headers: response.headers,
      body: response.body,
      bodyTruncated: response.bodyTruncated,
    };
  } catch (cause) {
    if (cause instanceof ApiTargetAdapterError) {
      return { ok: false, error: cause };
    }
    // Other errors are programmer errors — propagate.
    throw cause;
  }
}

// ── Schema helpers used in tests ────────────────────────────────────────────

export const apiDetectionSchema = z.object({
  endpoint: z.unknown().optional(),
  rationale: z.string().min(1),
  evidence: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
  severity: z.unknown().optional(),
});
