import { z } from 'zod';

import type { OwaspWebCategory } from './category';
import type { Severity } from './severity';

/**
 * Web app vulnerability scan — probe abstraction (T2.6).
 *
 * A `WebProbe` is the DAST equivalent of the AI scan's `StaticProbe` (T2.3): a
 * rule-based, LLM-free check that examines what Chromium loaded for one page and
 * decides, with an explainable rationale, whether a vulnerability is present.
 *
 * Where the AI probe DRIVES a target (`ScanTarget.send(attackInput)`), a web probe
 * OBSERVES a loaded page through a `PageContext`. This mirrors the relationship
 * "attack logic ↔ ScanTarget": probes depend only on the `PageContext` interface,
 * never on Playwright directly — so they are unit-testable without a browser, and
 * the engine stays clean (and easy to sandbox later, T3.2: probes touch no
 * filesystem, only the page surface).
 *
 * Probes are async because their checks may round-trip to Chromium (read cookies,
 * TLS details, DOM resources). That makes the per-probe timeout (Context §3) a
 * REAL guard: a probe whose browser round-trip hangs is cut and reported
 * `not-executed` — never "safe".
 */

/**
 * A resource referenced by the page's DOM (script/stylesheet/image/frame).
 * Extracted from the loaded page and used by integrity (SRI) and mixed-content
 * probes. This data comes from the untrusted page DOM, so it is Zod-validated
 * (`pageResourceSchema`) before any probe consumes it (CLAUDE.md §3).
 */
export const pageResourceSchema = z.object({
  /** Element kind that referenced the resource. */
  tag: z.enum(['script', 'link', 'img', 'iframe']),
  /** Absolute resource URL as resolved by the DOM (may be empty if unresolved). */
  url: z.string(),
  /** `rel` attribute (links only), lower-cased; null when absent. */
  rel: z.string().nullable(),
  /** Subresource Integrity attribute value; null when absent. */
  integrity: z.string().nullable(),
  /** `crossorigin` attribute value; null when absent. */
  crossorigin: z.string().nullable(),
});

export type PageResource = z.infer<typeof pageResourceSchema>;

/** Negotiated TLS details for an HTTPS response (subset Playwright exposes). */
export interface TlsSecurityDetails {
  /** e.g. `TLS 1.3`. Undefined for plain HTTP or when unavailable. */
  protocol?: string;
  issuer?: string;
  subjectName?: string;
  validFrom?: number;
  validTo?: number;
}

/** A cookie set for the page, with the security-relevant attributes. */
export interface ObservedCookie {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}

/**
 * Read-only view of one loaded page that probes operate on. The Playwright-backed
 * implementation (`PlaywrightPageContext`) memoizes the async accessors so N
 * probes never trigger N browser round-trips; tests use an in-memory fake.
 *
 * Synchronous accessors are cheap (already captured from the navigation response);
 * async accessors round-trip to Chromium and are the reason probes are async + each
 * guarded by its own timeout.
 */
export interface PageContext {
  /** URL requested by the scan (before redirects). */
  readonly requestedUrl: string;
  /** Final URL after redirects (`page.url()`). */
  readonly finalUrl: string;
  /** HTTP status of the main response. */
  readonly status: number;
  /** Response headers of the main document, with LOWER-CASED keys. */
  readonly responseHeaders: Readonly<Record<string, string>>;
  /** True when the final URL uses the https scheme. */
  readonly isHttps: boolean;
  /** Cookies set for the page. */
  cookies(): Promise<readonly ObservedCookie[]>;
  /** Negotiated TLS details, or null for plain HTTP / when unavailable. */
  securityDetails(): Promise<TlsSecurityDetails | null>;
  /** Rendered HTML of the page (size-capped by the implementation). */
  html(): Promise<string>;
  /** DOM-referenced subresources (scripts, stylesheets, images, frames). */
  resources(): Promise<readonly PageResource[]>;
}

/**
 * Outcome of running one web probe against a `PageContext`.
 *
 * Mirrors the AI scan's `DetectionResult`: `rationale` is ALWAYS populated
 * (explaining the positive OR negative decision — CLAUDE.md §3, security product),
 * and the detail fields are present only when `detected`.
 */
export interface WebDetection {
  /** True when the probe judges the page to exhibit the vulnerability. */
  detected: boolean;
  /** Explanation of the decision (positive or negative). Always populated. */
  rationale: string;
  /** Observed value that triggered detection — becomes evidence. Present iff detected. */
  evidence?: string;
  /** Optional extra metadata for the Finding evidence. */
  metadata?: Record<string, string>;
  /**
   * Optional severity override for context-dependent findings (e.g. permissive
   * CORS with credentials is worse than without). Falls back to `probe.severity`.
   */
  severity?: Severity;
}

/** Convenience constructor for a negative (no vulnerability) detection. */
export function notDetected(rationale: string): WebDetection {
  return { detected: false, rationale };
}

/**
 * A single DAST probe = metadata for a normalised `Finding` + a rule-based
 * `evaluate` over a `PageContext`. `id` is stable and unique across probes (base
 * for the `Finding` id and for cross-checking against `WEB_COVERAGE_MAP`).
 * `category` MUST be a `covered` web category (enforced by tests).
 */
export interface WebProbe {
  /** Stable, unique identity, e.g. `misconfig-missing-csp`. */
  id: string;
  /** Short technique label for documentation and evidence. */
  technique: string;
  /** OWASP web category of the Finding produced by this probe. */
  category: OwaspWebCategory;
  /** Default severity of the Finding if the probe triggers (may be overridden per detection). */
  severity: Severity;
  /** Concise Finding title. */
  title: string;
  /** Description of the vulnerability being tested. */
  description: string;
  /** Basic mitigation recommendation. */
  recommendation: string;
  /** Rule-based, LLM-free evaluation of the loaded page. */
  evaluate(ctx: PageContext): Promise<WebDetection>;
}
