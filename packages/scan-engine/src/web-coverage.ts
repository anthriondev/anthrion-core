import { owaspWebCategorySchema, type OwaspWebCategory } from './category';

/**
 * Web app vulnerability scan coverage map — completeness guard (T2.6 Context §2).
 *
 * EVERY category in `owaspWebCategorySchema` (A01–A10, OWASP Top 10:2025) MUST
 * have an entry here with an honest STATUS and a written rationale. The guard test
 * (`web-coverage.test.ts`) enforces that nothing is forgotten, and the `Record<…>`
 * type enforces completeness at compile time.
 *
 * Same mechanism and same PRINCIPLE as `LAYER1_COVERAGE_MAP` (T2.3/T2.5):
 * taxonomic honesty over cosmetic completeness. NO FAKE PROBES. A probe that
 * always "passes" without truly testing is worse than no probe — it gives the user
 * a false sense of safety. Categories that single-page DAST cannot honestly test
 * (without crawl, authentication, or internal/server-side knowledge) are recorded
 * as `phase-2`, not claimed as done.
 *
 * Status values:
 * - `covered` — single-page DAST against ONE live URL can meaningfully detect this
 *   category. Has ≥1 real probe in `WEB_PROBES` (enforced by test).
 * - `phase-2` — outside honest single-page DAST scope in Phase 1: needs crawl,
 *   authentication, multiple identities/sessions, a CVE/SBOM database, server-side
 *   visibility, active payload fuzzing, or human design review. Recorded as Phase
 *   2 work — NOT missing, NOT fake. Has 0 probes (enforced by test). MUST be
 *   justified.
 *
 * SCOPE NOTE (Context §1): Phase 1 is single-page, NO crawl. The "scan one page"
 * unit is built clean so Phase 1.5 ("Scanning Expansion") can add a
 * discover-many-pages → scan-each layer ON TOP without rebuilding — and several
 * `phase-2` categories below become reachable once crawl + active fuzzing land.
 */

export type WebCoverageStatus = 'covered' | 'phase-2';

export interface WebCoverageEntry {
  /** Category slug — must match the entry's key (enforced by test). */
  category: OwaspWebCategory;
  /** OWASP Top 10:2025 code, e.g. `A02:2025`. For traceability to the standard. */
  owaspCode: string;
  /** Coverage status (see `WebCoverageStatus`). */
  status: WebCoverageStatus;
  /** Written justification for this status. REQUIRED for every entry. */
  rationale: string;
}

export const WEB_COVERAGE_MAP: Readonly<Record<OwaspWebCategory, WebCoverageEntry>> = {
  'broken-access-control': {
    category: 'broken-access-control',
    owaspCode: 'A01:2025',
    status: 'phase-2',
    rationale:
      'Phase 2: authorization logic (IDOR, forced browsing, privilege escalation) can only be tested by requesting protected resources as different identities and comparing — requires authentication, multiple sessions, and crawl to enumerate resources. None exist in single-page unauthenticated DAST. (CORS misconfiguration, an access-control-adjacent but header-observable issue, is covered under security-misconfiguration.)',
  },
  'security-misconfiguration': {
    category: 'security-misconfiguration',
    owaspCode: 'A02:2025',
    status: 'covered',
    rationale:
      'Covered: directly observable from one response — missing/misconfigured security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), permissive CORS (Access-Control-Allow-Origin: *), software/version disclosure (Server, X-Powered-By), and weak cookie flags (missing HttpOnly, SameSite=None without Secure). Real rule-based probes, no LLM.',
  },
  'software-supply-chain-failures': {
    category: 'software-supply-chain-failures',
    owaspCode: 'A03:2025',
    status: 'phase-2',
    rationale:
      'Phase 2: judging whether a dependency is vulnerable/compromised requires a CVE/advisory database and an SBOM. Merely observing that a library loads (and guessing its version from the DOM) is not an honest vulnerability test — presence ≠ vulnerability, and version guessing is false-positive prone. Consistent with the AI map marking supply-chain phase-2. (Loading third-party code WITHOUT integrity verification is a distinct, observable issue covered under software-or-data-integrity-failures via Subresource Integrity.)',
  },
  'cryptographic-failures': {
    category: 'cryptographic-failures',
    owaspCode: 'A04:2025',
    status: 'covered',
    rationale:
      'Covered: transport security is observable on one page — site served over plain HTTP (cleartext), missing HSTS on HTTPS, weak negotiated TLS version (from the response security details), cookies lacking the Secure flag, and mixed content (HTTP subresources on an HTTPS page). Real rule-based probes, no LLM.',
  },
  injection: {
    category: 'injection',
    owaspCode: 'A05:2025',
    status: 'phase-2',
    rationale:
      'Phase 2: reliable injection detection (SQLi, reflected/stored/DOM XSS, command injection) requires actively submitting crafted payloads into parameters and forms, then observing responses — plus crawl to discover those inputs. Doing it on one unsolicited page without active fuzzing is either fake (no real test) or invasive. The one passively-observable XSS-impact factor (a permissive/missing CSP) is reported under security-misconfiguration. Active injection fuzzing arrives with Phase 1.5.',
  },
  'insecure-design': {
    category: 'insecure-design',
    owaspCode: 'A06:2025',
    status: 'phase-2',
    rationale:
      'Phase 2: an architectural/design flaw (missing threat-model control, abusable business logic) cannot be detected by an automated DAST probe against a single page — it requires human design review and threat modeling. Marking it covered would be dishonest. Same nature as insecure-design being out of automated scope in the AI taxonomy.',
  },
  'authentication-failures': {
    category: 'authentication-failures',
    owaspCode: 'A07:2025',
    status: 'phase-2',
    rationale:
      'Phase 2: testing authentication (weak-credential/brute-force protection, session fixation, MFA, lockout) requires interacting with a login flow with credentials and observing multiple sessions — none available to single-page unauthenticated DAST, and requires crawl to even locate the login. (Session-cookie hardening, an observable adjacent signal, is covered via the cookie flag probes under cryptographic-failures / security-misconfiguration.)',
  },
  'software-or-data-integrity-failures': {
    category: 'software-or-data-integrity-failures',
    owaspCode: 'A08:2025',
    status: 'covered',
    rationale:
      'Covered for the observable case: cross-origin <script>/<link rel=stylesheet> loaded WITHOUT a Subresource Integrity (integrity) attribute — the page trusts third-party code with no integrity verification, a genuine, single-page-observable integrity failure. (Insecure deserialization and unsigned-update flows are server-side and remain Phase 2; this entry is honest about covering the SRI-observable subset.)',
  },
  'security-logging-and-alerting-failures': {
    category: 'security-logging-and-alerting-failures',
    owaspCode: 'A09:2025',
    status: 'phase-2',
    rationale:
      'Phase 2: whether the target logs, monitors, and alerts on security events is server-side behavior, invisible to a black-box external observer. There is no honest single-page signal for it — a probe here would always "pass" by construction, which is exactly the fake probe the rules forbid.',
  },
  'mishandling-of-exceptional-conditions': {
    category: 'mishandling-of-exceptional-conditions',
    owaspCode: 'A10:2025',
    status: 'covered',
    rationale:
      'Covered for the observable case: the scanned response itself reveals a mishandled exceptional condition — a 5xx server error returned to the user, or a verbose stack trace / framework debug page (Werkzeug, Whoops/Laravel, Rails, ASP.NET, Python traceback, SQL error) leaking internals. Detected with specific signatures to keep false positives low. (Systematically forcing exceptional conditions across many inputs needs active fuzzing + crawl = Phase 1.5; this entry is honest about covering what is observable on the given page.)',
  },
};

/** All web category slugs that must be covered by the map, derived from the enum. */
export const WEB_CATEGORY_SLUGS: readonly OwaspWebCategory[] = owaspWebCategorySchema.options;

/** Retrieve the coverage entry for a web category. */
export function webCoverageFor(category: OwaspWebCategory): WebCoverageEntry {
  return WEB_COVERAGE_MAP[category];
}

/** List web coverage entries with a given status. */
export function webCategoriesByStatus(status: WebCoverageStatus): WebCoverageEntry[] {
  return WEB_CATEGORY_SLUGS.map((slug) => WEB_COVERAGE_MAP[slug]).filter(
    (entry) => entry.status === status,
  );
}
