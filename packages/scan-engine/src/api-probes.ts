import { buildEndpointUrl, tryRequest, type ApiDetection, type ApiProbe } from './api-probe';
import type { ApiEndpoint, ApiTarget } from './api-target';

/**
 * Curated API security probes (Phase 1.5 Sprint A1, T-A1.2).
 *
 * Five probes covering four OWASP API Top 10:2023 categories that Sprint A1
 * can honestly test without authentication context. Categories outside this
 * scope (BOLA, BFLA, BOPLA, business flows, SSRF, unsafe API consumption) are
 * recorded as `phase-2` in `API_COVERAGE_MAP` — NO FAKE PROBES.
 *
 * Probe design notes:
 *  - Each probe runs against the WHOLE target (raw or spec). Per-endpoint
 *    probes iterate `target.endpoints()`; target-level probes do not.
 *  - In raw mode the target enumerates only one endpoint, so per-endpoint
 *    probes do one round-trip. The honest "we tested 1 of N" caveat is
 *    surfaced at the scan-report layer via `target.coverage === 'raw'`.
 *  - Probes catch `ApiTargetAdapterError` from individual requests via
 *    `tryRequest` and continue — one failing request does not abort the
 *    probe. Unrecoverable probe-internal errors propagate; the runner marks
 *    the probe `not-executed`.
 *  - Credential values from `spec.auth` never appear in evidence (CLAUDE.md §3).
 */

/**
 * api:server-software-disclosure — API8:2023.
 *
 * Detects identifying software/version banners in response headers
 * (`Server`, `X-Powered-By`). Mirrors the web probe of the same family, scoped
 * to whatever endpoints the API target exposes. Bare values like `nginx` or
 * `Apache` (no version) are non-disclosing — only flag when the header is
 * present with content; a versioned banner is high-signal for the report.
 */
const serverSoftwareDisclosureProbe: ApiProbe = {
  id: 'api:server-software-disclosure',
  technique: 'Response header inspection',
  category: 'api-security-misconfiguration',
  severity: 'Low',
  title: 'API exposes server software / version in response headers',
  description:
    'The API\'s response headers reveal the server software (Server) or web framework (X-Powered-By). An attacker can use this to target known vulnerabilities in the disclosed stack.',
  recommendation:
    'Strip or generalise Server and X-Powered-By response headers on the API server / reverse proxy.',
  evaluate: async (target) => {
    const detections: ApiDetection[] = [];
    for (const endpoint of target.endpoints()) {
      const outcome = await tryRequest(target, {
        endpoint,
        url: buildEndpointUrl(target, endpoint),
        method: endpoint.method,
      });
      if (!outcome.ok || outcome.headers === undefined) continue;
      const xPoweredBy = outcome.headers['x-powered-by'];
      const server = outcome.headers.server;
      if (xPoweredBy === undefined && server === undefined) continue;

      const parts: string[] = [];
      const metadata: Record<string, string> = {};
      if (server !== undefined) {
        parts.push(`Server: ${server}`);
        metadata.server = server;
      }
      if (xPoweredBy !== undefined) {
        parts.push(`X-Powered-By: ${xPoweredBy}`);
        metadata.xPoweredBy = xPoweredBy;
      }
      detections.push({
        endpoint,
        rationale: `Response from ${endpoint.method} ${endpoint.pathTemplate} discloses server software via headers.`,
        evidence: parts.join('; '),
        metadata,
      });
    }
    return detections;
  },
};

/**
 * api:permissive-cors — API8:2023.
 *
 * Detects `Access-Control-Allow-Origin: *`. Severity is bumped to High when
 * combined with `Access-Control-Allow-Credentials: true` (T-FIX.6: the two
 * variants are materially different — browsers reject `*` + credentials per
 * spec, but middleware emitting both is a misconfiguration with its own trust
 * implications, and proxies have been known to honour both). Each detection
 * carries its own description so the finding text matches exactly what was
 * observed — no implication that wildcard alone permits credentialed reads.
 */
const CORS_WILDCARD_DESCRIPTION =
  'The API responds with Access-Control-Allow-Origin: *, allowing any origin to read its non-credentialed responses from a browser context. Where the endpoint should be reachable only by a known set of origins, this widens the cross-origin attack surface.';
const CORS_WILDCARD_WITH_CREDENTIALS_DESCRIPTION =
  'The API responds with Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true. Conformant browsers reject this combination, but middleware emitting it is a clear server-side misconfiguration — and intermediaries (proxies, non-browser clients) have been observed honouring both, leaving a credentialed cross-origin trust failure exposed.';

const permissiveCorsProbe: ApiProbe = {
  id: 'api:permissive-cors',
  technique: 'CORS preflight / response header inspection',
  category: 'api-security-misconfiguration',
  severity: 'Medium',
  title: 'API exposes permissive CORS policy',
  // Default description matches the wildcard-alone case (the more common
  // detection); the credentials variant overrides it per-detection.
  description: CORS_WILDCARD_DESCRIPTION,
  recommendation:
    'Restrict Access-Control-Allow-Origin to a specific allow-list of trusted origins; never combine wildcard origin with allow-credentials.',
  evaluate: async (target) => {
    const detections: ApiDetection[] = [];
    for (const endpoint of target.endpoints()) {
      const outcome = await tryRequest(target, {
        endpoint,
        url: buildEndpointUrl(target, endpoint),
        method: endpoint.method,
      });
      if (!outcome.ok || outcome.headers === undefined) continue;
      const allowOrigin = outcome.headers['access-control-allow-origin'];
      if (allowOrigin !== '*') continue;

      const allowCreds = outcome.headers['access-control-allow-credentials'];
      const withCredentials = allowCreds?.toLowerCase() === 'true';
      detections.push({
        endpoint,
        severity: withCredentials ? 'High' : 'Medium',
        description: withCredentials
          ? CORS_WILDCARD_WITH_CREDENTIALS_DESCRIPTION
          : CORS_WILDCARD_DESCRIPTION,
        rationale: withCredentials
          ? `${endpoint.method} ${endpoint.pathTemplate} permits Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true — a serious cross-origin trust failure.`
          : `${endpoint.method} ${endpoint.pathTemplate} permits Access-Control-Allow-Origin: *.`,
        evidence: withCredentials
          ? 'Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true'
          : 'Access-Control-Allow-Origin: *',
        metadata: {
          allowOrigin: '*',
          ...(withCredentials ? { allowCredentials: 'true' } : {}),
        },
      });
    }
    return detections;
  },
};

/**
 * api:docs-exposed — API9:2023.
 *
 * Probes a small list of well-known specification / documentation paths at the
 * target's origin (NOT under the spec's basePath — these tools register at
 * fixed paths by convention). A 200 response containing JSON / HTML with
 * documentation signals is a real improper-inventory finding: the same spec
 * gives an attacker the inventory of endpoints to attack.
 *
 * Target-level probe (one detection per discovered path, not per endpoint).
 */
const DOCS_PATHS_TO_PROBE: readonly string[] = [
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger.yaml',
  '/v3/api-docs',
  '/api-docs',
  '/swagger-ui.html',
  '/swagger-ui/index.html',
  '/docs',
  '/redoc',
];

const docsExposedProbe: ApiProbe = {
  id: 'api:docs-exposed',
  technique: 'Well-known documentation path probe',
  category: 'improper-inventory-management',
  severity: 'Medium',
  title: 'API specification / documentation is publicly accessible',
  description:
    'A well-known API specification or documentation path returns a 200 response with the schema or UI. An unauthenticated attacker can enumerate every endpoint, parameter, and authentication requirement of the API.',
  recommendation:
    'Restrict access to spec/documentation paths (auth-gate or remove from production); if exposure is intentional, ensure the public spec does not list internal-only endpoints.',
  evaluate: async (target) => {
    if (target.endpoints().length === 0) return [];
    // Borrow an existing endpoint to satisfy the `ApiRequest.endpoint` field
    // (the request goes to a documentation path, not the endpoint's path).
    const [borrowedEndpoint] = target.endpoints();
    if (borrowedEndpoint === undefined) return [];

    const detections: ApiDetection[] = [];
    for (const docsPath of DOCS_PATHS_TO_PROBE) {
      const url = `${target.baseUrl}${docsPath}`;
      const outcome = await tryRequest(target, {
        endpoint: borrowedEndpoint,
        url,
        method: 'GET',
      });
      if (!outcome.ok || outcome.status === undefined) continue;
      if (outcome.status !== 200) continue;
      if (!looksLikeDocs(outcome.body ?? '', outcome.headers ?? {})) continue;

      detections.push({
        rationale: `GET ${docsPath} returned 200 with content that looks like an API specification or documentation page — unauthenticated attackers can use it to enumerate endpoints.`,
        evidence: `GET ${url} → 200`,
        metadata: {
          docsPath,
          contentType: outcome.headers?.['content-type'] ?? 'unknown',
        },
      });
    }
    return detections;
  },
};

/**
 * Heuristic: does this body / Content-Type look like API documentation? Used
 * by `docs-exposed` to avoid flagging arbitrary 200 responses (e.g. a SPA's
 * index.html caught by `/docs`).
 */
function looksLikeDocs(body: string, headers: Readonly<Record<string, string>>): boolean {
  const contentType = (headers['content-type'] ?? '').toLowerCase();
  // JSON spec — usually OpenAPI/Swagger; require an indicative key.
  if (contentType.includes('json')) {
    return /"(?:openapi|swagger)"\s*:/.test(body);
  }
  // YAML spec.
  if (contentType.includes('yaml') || contentType.includes('yml')) {
    return /^(openapi|swagger)\s*:/m.test(body);
  }
  // HTML — look for the canonical Swagger UI / Redoc / ApiDoc markers.
  if (contentType.includes('html')) {
    return (
      /swagger-ui/i.test(body) ||
      /<redoc/i.test(body) ||
      /api[\s_-]?docs/i.test(body) ||
      /openapi[\s_-]?explorer/i.test(body)
    );
  }
  return false;
}

/**
 * api:no-rate-limit — API4:2023.
 *
 * Sends a small burst (5 identical requests, no artificial delay) against each
 * endpoint and reports per-endpoint when:
 *  - no response carries `429`, AND
 *  - no response carries `Retry-After` / `X-RateLimit-*` headers.
 *
 * 5 requests is far below any reasonable DoS threshold but is enough to trigger
 * any sane rate limiter (typical thresholds are 10+ req/sec). Endpoints behind
 * a WAF that drops the connection without a body produce `ApiTargetAdapterError`
 * — which IS a rate-limit signal (silent drop is a form of throttling) and is
 * counted as such.
 *
 * Target-level burst is intentional: probing multiple endpoints sequentially
 * is fine; the burst is per-endpoint and tightly scoped.
 */
const BURST_SIZE = 5;

const noRateLimitProbe: ApiProbe = {
  id: 'api:no-rate-limit',
  technique: 'Burst-request rate-limit observation',
  category: 'unrestricted-resource-consumption',
  severity: 'Medium',
  title: 'API endpoint shows no observable rate-limiting',
  description:
    'A burst of 5 identical requests to the endpoint completed without any rate-limit signal (no 429 status, no Retry-After header, no X-RateLimit-* headers, no connection-level throttling). The API may be exposed to brute-force, scraping, or resource-exhaustion abuse.',
  recommendation:
    'Apply rate limiting at the API gateway or application layer (per IP, per token, per route as appropriate) and emit Retry-After / X-RateLimit-* headers so clients can back off cooperatively.',
  evaluate: async (target) => {
    const detections: ApiDetection[] = [];
    for (const endpoint of target.endpoints()) {
      const observation = await burstObserve(target, endpoint);
      if (observation.signalDetected) continue;
      // T-FIX.5: if every observed status is a "not-existing" code (404/410), the
      // absence of a rate-limit signal there is not evidence of a missing rate
      // limit — there is nothing at that path to rate-limit. Emitting the finding
      // is misleading noise (visible in the Petstore-spec scan, where many of the
      // 57 findings were burst-on-404 reports). Skip the detection in that case.
      if (
        observation.statusesSeen.length === BURST_SIZE &&
        observation.statusesSeen.every((s) => s === 404 || s === 410)
      ) {
        continue;
      }
      detections.push({
        endpoint,
        rationale: `${BURST_SIZE} consecutive ${endpoint.method} ${endpoint.pathTemplate} requests completed without any rate-limit signal (no 429, no Retry-After, no X-RateLimit-* header, no connection-level throttling).`,
        evidence: `${BURST_SIZE}× ${endpoint.method} ${endpoint.pathTemplate} → ${observation.statusesSeen.join(', ')}`,
        metadata: {
          burstSize: String(BURST_SIZE),
          statusesSeen: observation.statusesSeen.join(','),
        },
      });
    }
    return detections;
  },
};

interface BurstObservation {
  signalDetected: boolean;
  statusesSeen: number[];
}

async function burstObserve(target: ApiTarget, endpoint: ApiEndpoint): Promise<BurstObservation> {
  const statusesSeen: number[] = [];
  let signalDetected = false;
  for (let i = 0; i < BURST_SIZE; i++) {
    const outcome = await tryRequest(target, {
      endpoint,
      url: buildEndpointUrl(target, endpoint),
      method: endpoint.method,
    });
    if (!outcome.ok) {
      // Connection-level throttling (silent drop) IS a rate-limit signal.
      signalDetected = true;
      continue;
    }
    if (outcome.status !== undefined) statusesSeen.push(outcome.status);
    if (outcome.status === 429) {
      signalDetected = true;
      continue;
    }
    const headers = outcome.headers ?? {};
    if (
      headers['retry-after'] !== undefined ||
      headers['x-ratelimit-limit'] !== undefined ||
      headers['x-ratelimit-remaining'] !== undefined ||
      headers['x-ratelimit-reset'] !== undefined ||
      headers['ratelimit-limit'] !== undefined ||
      headers['ratelimit-remaining'] !== undefined
    ) {
      signalDetected = true;
    }
  }
  return { signalDetected, statusesSeen };
}

/**
 * The curated probe set for Sprint A1. Stable order — tests rely on `id`
 * uniqueness; the order itself is for human readability.
 *
 * NOTE: A `broken-authentication` probe (`api:accepts-bogus-token`) was
 * designed and then DROPPED before shipping. The probe compared a baseline
 * response to a request with a clearly-bogus bearer token and flagged when
 * both succeeded. On a TRULY public endpoint that legitimately returns 200
 * regardless of auth (health, version, public read-only data) the probe would
 * always fire — a false positive against intended behavior. Distinguishing
 * "should be protected" from "intentionally public" requires a signal the
 * `ApiTarget` interface does not currently expose. Until that signal exists
 * (auth-context sprint), `broken-authentication` is honestly recorded as
 * `phase-2` in `API_COVERAGE_MAP` rather than covered with an unsound probe.
 * NO FAKE PROBES is the rule that retired this one.
 */
export const API_PROBES: readonly ApiProbe[] = Object.freeze([
  serverSoftwareDisclosureProbe,
  permissiveCorsProbe,
  docsExposedProbe,
  noRateLimitProbe,
]);
