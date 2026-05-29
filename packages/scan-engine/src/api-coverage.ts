import { owaspApiCategorySchema, type OwaspApiCategory } from './category';

/**
 * API security scan coverage map — completeness guard (Phase 1.5 Sprint A1, T-A1.2).
 *
 * EVERY category in `owaspApiCategorySchema` (API1–API10, OWASP API Security
 * Top 10:2023) MUST have an entry here with an honest STATUS and a written
 * rationale. The guard test (`api-coverage.test.ts`) enforces that nothing is
 * forgotten, and the `Record<…>` type enforces completeness at compile time.
 *
 * Same mechanism and PRINCIPLE as `WEB_COVERAGE_MAP` (T2.6) and
 * `LAYER1_COVERAGE_MAP` (T2.3): taxonomic honesty over cosmetic completeness.
 * NO FAKE PROBES. A probe that always "passes" without truly testing is worse
 * than no probe — it gives the user a false sense of safety. Categories that
 * Sprint A1 cannot honestly test (without authentication, multiple identities,
 * business-flow context, or active payload fuzzing) are recorded as `phase-2`,
 * not claimed as done.
 *
 * SCOPE NOTE: Sprint A1 is the introduction of API scanning. The unit is built
 * clean so future sprints — adding authenticated scans, multi-identity
 * comparison, and active payload fuzzing — can flip categories from `phase-2`
 * to `covered` by adding probes WITHOUT reshaping this map.
 *
 * Status values:
 *  - `covered` — Sprint A1 has ≥1 real probe in `API_PROBES` (enforced by test).
 *  - `phase-2` — outside honest Sprint A1 scope. 0 probes (enforced by test).
 *    Phase 2 here means: requires functionality not yet built (auth context,
 *    multi-identity, business-flow modelling, active fuzzing). MUST be justified.
 */

export type ApiCoverageStatus = 'covered' | 'phase-2';

export interface ApiCoverageEntry {
  /** Category slug — must match the entry's key (enforced by test). */
  category: OwaspApiCategory;
  /** OWASP API Top 10:2023 code, e.g. `API1:2023`. Traceability to the standard. */
  owaspCode: string;
  /** Coverage status (see `ApiCoverageStatus`). */
  status: ApiCoverageStatus;
  /** Written justification for this status. REQUIRED for every entry. */
  rationale: string;
}

export const API_COVERAGE_MAP: Readonly<Record<OwaspApiCategory, ApiCoverageEntry>> = {
  'broken-object-level-authorization': {
    category: 'broken-object-level-authorization',
    owaspCode: 'API1:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: BOLA needs an authenticated session and tamperable object identifiers (e.g. /users/{id} as alice fetching bob). Sprint A1 is unauthenticated and either single-endpoint (raw) or spec-enumerated; without identity context the only "test" would be to submit IDs and grade response shape — a heuristic that produces false positives on every endpoint that publicly accepts an ID. Honest deferral until auth context lands.',
  },
  'broken-authentication': {
    category: 'broken-authentication',
    owaspCode: 'API2:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: a bogus-token / tampered-credential probe was prototyped (compare baseline vs tampered status; flag when both succeed). It was dropped before shipping because a TRULY public endpoint that legitimately serves any client (health, version, public read-only data) would trigger it as a false positive against intended behavior. Distinguishing "should be protected" from "intentionally public" needs an auth-protection signal the ApiTarget interface does not currently expose. Login-flow weaknesses (weak passwords, missing MFA, session fixation) also remain Phase 2 — they need login interaction and crawl.',
  },
  'broken-object-property-level-authorization': {
    category: 'broken-object-property-level-authorization',
    owaspCode: 'API3:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: BOPLA combines old "Excessive Data Exposure" and "Mass Assignment" — testing both needs authenticated sessions plus comparison of response bodies across identities (data exposure) and PUT/POST payloads with extra fields (mass assignment). Sprint A1 has neither identities nor authenticated state to compare against; an unauthenticated scan would either be fake (flag every endpoint with a JSON body) or invasive.',
  },
  'unrestricted-resource-consumption': {
    category: 'unrestricted-resource-consumption',
    owaspCode: 'API4:2023',
    status: 'covered',
    rationale:
      'Covered for the observable signal: a small burst of identical requests (5 within ~1s — well below DoS thresholds and quickly enough to trigger any sane rate limiter) is sent against the configured endpoint(s). If no response carries 429, Retry-After, or X-RateLimit-* headers, AND no request is short-circuited, we report the absence of any observable rate-limit signal. Resource-consumption forms that require sustained load or payload size limits are Phase 2.',
  },
  'broken-function-level-authorization': {
    category: 'broken-function-level-authorization',
    owaspCode: 'API5:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: BFLA needs at least two identity tiers (e.g. user vs admin) and the ability to test whether the user identity can call admin-only operations. Sprint A1 has no identities, no role context, and no way to honestly grade "this should/should not have worked". Verb tampering (GET on a POST-only endpoint) is observable but produces too many false positives on REST APIs that legitimately accept OPTIONS / HEAD — defer until role context is available.',
  },
  'unrestricted-access-to-sensitive-business-flows': {
    category: 'unrestricted-access-to-sensitive-business-flows',
    owaspCode: 'API6:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: identifying "sensitive business flows" (account-creation abuse, ticket-scalping, voucher exploitation) requires modelling the API\'s business semantics — which endpoints together form a flow, what represents abuse. This is a design-level judgement; an automated probe without that model would either invent flows (fake) or flag every multi-endpoint sequence (noise). Honest deferral.',
  },
  'server-side-request-forgery': {
    category: 'server-side-request-forgery',
    owaspCode: 'API7:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: SSRF detection needs active payload fuzzing — submitting URLs (localhost, cloud metadata endpoints, internal hostnames) into endpoint parameters and observing whether the server fetches them. Sprint A1 does not do active payload fuzzing; doing so safely also requires an out-of-band canary callback channel. Same Phase 2 boundary as web "injection".',
  },
  'api-security-misconfiguration': {
    category: 'api-security-misconfiguration',
    owaspCode: 'API8:2023',
    status: 'covered',
    rationale:
      'Covered: directly observable from response headers — software/version disclosure (Server, X-Powered-By), permissive CORS (Access-Control-Allow-Origin: * — High severity when combined with allow-credentials). Single rule-based check per signal, no LLM. Misconfig categories that require knowing what the API SHOULD have configured (e.g. missing CSP on a JSON API where CSP is not applicable) are deliberately not flagged — false positives are worse than honest gaps in a security product.',
  },
  'improper-inventory-management': {
    category: 'improper-inventory-management',
    owaspCode: 'API9:2023',
    status: 'covered',
    rationale:
      'Covered for the observable signal: well-known specification / documentation paths (`/openapi.json`, `/swagger.json`, `/api-docs`, `/swagger-ui`, `/docs`, `/v3/api-docs`) probed with GET. A 200 response leaking the API specification is a real improper-inventory finding — the same spec gives an attacker the endpoint inventory. Finding 0 results is not a guarantee (only common paths are probed) — the rationale carries that honestly.',
  },
  'unsafe-consumption-of-apis': {
    category: 'unsafe-consumption-of-apis',
    owaspCode: 'API10:2023',
    status: 'phase-2',
    rationale:
      'Phase 2: this category is about how the target API consumes OTHER APIs (trusting third-party responses, mishandling external errors) — visible only with internal/server-side knowledge or by triggering the target\'s outbound calls in a controlled way. No honest external observable signal in Sprint A1.',
  },
};

/** All API category slugs derived from the enum. */
export const API_CATEGORY_SLUGS: readonly OwaspApiCategory[] = owaspApiCategorySchema.options;

/** Retrieve the coverage entry for an API category. */
export function apiCoverageFor(category: OwaspApiCategory): ApiCoverageEntry {
  return API_COVERAGE_MAP[category];
}

/** List API coverage entries with a given status. */
export function apiCategoriesByStatus(status: ApiCoverageStatus): ApiCoverageEntry[] {
  return API_CATEGORY_SLUGS.map((slug) => API_COVERAGE_MAP[slug]).filter(
    (entry) => entry.status === status,
  );
}
