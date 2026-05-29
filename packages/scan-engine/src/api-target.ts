import { z } from 'zod';

/**
 * API scan target adapter (ARCHITECTURE.md §4.1 — same adapter-abstraction rule
 * applied to API-shaped targets).
 *
 * Where the AI scan's `ScanTarget` is chat-completion shaped (string in →
 * string out), an API target is HTTP-shaped: probes send a crafted request and
 * inspect status/headers/body. This is a parallel interface, not a reuse of
 * `ScanTarget` — same reason the web scan introduced `PageContext` instead of
 * overloading `ScanTarget`.
 *
 * Two modes hide behind this interface (Sprint A1):
 *  - `spec` — adapter built from an OpenAPI/Swagger document; `endpoints()`
 *    enumerates every operation in the spec.
 *  - `raw` — adapter built from a single endpoint URL; `endpoints()` returns
 *    that one operation. The probe / report layer reads `coverage` to mark
 *    raw-mode results as honestly shallower (raw mode does not know every
 *    endpoint of the API).
 *
 * Probe logic above this interface MUST NOT branch on the mode; it depends on
 * the interface only.
 */

/** HTTP method recognised by the API scan adapter. */
export const apiHttpMethodSchema = z.enum([
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'HEAD',
  'OPTIONS',
]);

export type ApiHttpMethod = z.infer<typeof apiHttpMethodSchema>;

/**
 * Coverage breadth of an `ApiTarget`. `spec` enumerates every endpoint declared
 * in the OpenAPI document; `raw` knows only the single endpoint the user gave.
 * Probes and the report layer use this to mark coverage honestly (Phase 1 honesty
 * rule — raw mode is NOT silently reported as if it covered the whole API).
 */
export const apiCoverageModeSchema = z.enum(['spec', 'raw']);

export type ApiCoverageMode = z.infer<typeof apiCoverageModeSchema>;

/**
 * One endpoint known to the target. In spec mode the adapter produces one
 * `ApiEndpoint` per operation in the OpenAPI document; in raw mode there is
 * exactly one. `pathTemplate` is the OpenAPI template (spec mode, e.g.
 * `/users/{id}`) or the concrete path (raw mode, e.g. `/users/123`).
 */
export const apiEndpointSchema = z.object({
  method: apiHttpMethodSchema,
  pathTemplate: z.string().min(1),
  /** OpenAPI operationId when available; null in raw mode (no spec → no id). */
  operationId: z.string().nullable(),
});

export type ApiEndpoint = z.infer<typeof apiEndpointSchema>;

/**
 * One HTTP request the probe asks the target to send. The probe is responsible
 * for substituting path/query parameters before constructing `url` — it knows
 * what values it wants to send (e.g. a tampered id for a BOLA test).
 *
 * `url` MUST share the target's `baseUrl` origin; the adapter enforces this so
 * a probe cannot accidentally drive traffic to a different host.
 */
export const apiRequestSchema = z.object({
  endpoint: apiEndpointSchema,
  url: z.string().url(),
  method: apiHttpMethodSchema,
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
});

export type ApiRequest = z.infer<typeof apiRequestSchema>;

/**
 * Response from the API target. Body is captured as text and size-capped by the
 * adapter (`bodyTruncated` indicates the cap was hit). This is untrusted
 * external data and is Zod-validated by the adapter before any probe consumes
 * it (CLAUDE.md §3).
 */
export const apiResponseSchema = z.object({
  status: z.number().int().min(100).max(599),
  /** Response headers with LOWER-CASED keys (consistent with `PageContext`). */
  headers: z.record(z.string(), z.string()),
  body: z.string(),
  /** True when the body was truncated due to the capture cap. */
  bodyTruncated: z.boolean(),
});

export type ApiResponse = z.infer<typeof apiResponseSchema>;

/**
 * API target adapter interface. Same adapter-abstraction rule as `ScanTarget`
 * (`target.ts`) and `PageContext` (`web-probe.ts`): probe logic depends on the
 * interface only, never on the concrete mode.
 */
export interface ApiTarget {
  /** Origin of the API (e.g. `https://api.example.com`). All requests stay within this origin. */
  readonly baseUrl: string;
  /** Coverage breadth — `spec` (all operations) or `raw` (one endpoint). */
  readonly coverage: ApiCoverageMode;
  /** Endpoints known to the target. Length ≥ 1; raw mode returns exactly one. */
  endpoints(): readonly ApiEndpoint[];
  /** Send a crafted request and return the validated response. */
  request(req: ApiRequest): Promise<ApiResponse>;
}

/**
 * Error thrown by an API target adapter when it cannot obtain a valid response
 * (timeout, network failure, non-2xx and non-error response that violates the
 * schema, malformed body). Distinct from `TargetAdapterError` which belongs to
 * the AI `ScanTarget`; keeping the two parallel makes the engine's error
 * surface easy to read.
 *
 * Error messages MUST NOT contain credential values (same rule as the AI
 * endpoint adapter — see `config.ts:endpointAuthSchema` security note).
 */
export class ApiTargetAdapterError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ApiTargetAdapterError';
  }
}
