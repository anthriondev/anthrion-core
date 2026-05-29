import { z } from 'zod';

import type { OwaspWeb3Category } from './category';
import type { Severity } from './severity';
import type { Web3DAppTarget } from './web3-target';

/**
 * Web3 L2 — dApp frontend / infrastructure probe abstraction (Sprint A3, T-A3.6).
 *
 * L2 probes consume the loaded-page surface (`Web3DAppTarget extends PageContext`)
 * AND, for the bundle-drift / DNS sub-checks, perform their OWN small, scoped
 * outbound requests (CDN registry lookups, DNS resolution). The contract
 * mirrors `Web3L1Probe` and `Web3L3Probe`: one probe per L2 slug from
 * `owaspWeb3CategorySchema`, no LLM, indicator-not-verdict severity language
 * (T-FIX.6 lesson preserved).
 *
 * Honest coverage rule (mirrors L1 / L3):
 *  - A probe that cannot reach the CDN / DNS / OCSP endpoint it needs to make
 *    a real judgement returns NO detection AND emits a per-probe coverage
 *    note via `Web3L2Detection.coverageNotes` — the runner surfaces it as a
 *    probe-specific coverage gap kind. NEVER a clean bill, NEVER an invented
 *    finding when the input was missing.
 *  - "I checked and the indicator isn't present" returns an empty detection
 *    list with no coverage notes. Silence is silence.
 *
 * Calibration (T-A3.6 spec):
 *  - `dapp-frontend-integrity` (SRI absence per script + bundle-drift hash
 *    mismatch). Medium per offending script for SRI absence (every external
 *    script is its own report row — the spec calls out "per external script
 *    tag, not just one summary"); High on a bundle-drift hash mismatch
 *    (CDN-served file content does not match what the page embedded — the
 *    closest L2 has to a verdict signal, but still phrased as indicator).
 *  - `known-bad-domain-reference` — High. Match is exact-hostname against a
 *    small in-repo curated blocklist of wallet-drainer / phishing hosts; the
 *    name itself does not prove the dApp is malicious (it could embed a
 *    legitimate fork hosted at a marked domain), but the hostname is a real
 *    structural fact deserving the user's attention.
 *  - `dapp-dns-or-tls-hygiene` — Medium-High. TLS hygiene sub-checks
 *    (issuer reputation, cert age, near-expiry, missing protocol negotiation)
 *    each emit Medium individually; DNS sub-checks (NS resolution health)
 *    contribute Medium. Sub-checks that the probe cannot perform from inside
 *    the sandbox (DNSSEC validation, full WHOIS) are honestly skipped via the
 *    coverage-notes mechanism.
 *
 * No L2 probe ever emits Critical: the L1 layer reserves that for the
 * EIP-7702 SetCode case, and L3 aggregate composition caps elevation at High.
 */

/** Outcome of one L2 probe against the target. */
export interface Web3L2Detection {
  /** Optional sub-resource (e.g. one offending external script) the detection
   * pertains to. Present iff the detection is per-resource; absent for
   * target-level detections. Used to build a stable per-detection
   * `Finding.id`. */
  subjectKey?: string;
  /** Explanation of the positive decision. ALWAYS populated. */
  rationale: string;
  /** Observed value(s) that triggered detection — becomes evidence.output. */
  evidence: string;
  /** Optional extra metadata for the Finding evidence. Truncated at the
   * detection boundary — never carry a full page / response blob. */
  metadata?: Record<string, string>;
  /** Optional severity override for context-dependent findings. */
  severity?: Severity;
  /** Optional description override when the same probe has materially
   * different failure modes (e.g. SRI absence vs bundle-drift hash mismatch). */
  description?: string;
}

/**
 * Per-probe coverage note describing a sub-check the probe COULD NOT perform.
 * The runner aggregates these into a coverage gaps list for the report; they
 * are NOT findings, they are honest declarations that part of the indicator
 * surface wasn't inspected (sub-agent rubric §10, §11).
 */
export interface Web3L2CoverageNote {
  /** Short, stable kind slug — `web3-l2-<subcheck>-skipped` style. The worker
   * (T-A3.7) materialises these into `coverageGap` objects against the shared
   * schema; renaming requires updating both sides deliberately. */
  kind: string;
  /** Honest description of what wasn't checked + why. Reader-actionable. */
  reason: string;
}

/** Result of one probe's evaluation — both detections AND any coverage notes
 * the probe collected. The runner builds Findings from `detections` and
 * propagates `coverageNotes` into the report's coverage-gap list. */
export interface Web3L2EvaluationResult {
  detections: readonly Web3L2Detection[];
  coverageNotes?: readonly Web3L2CoverageNote[];
}

/** A single Web3 L2 probe. */
export interface Web3L2Probe {
  /** Stable probe id. Prefix `web3:l2:` keeps it distinct from L1 / L3 / api /
   * web ids. */
  id: string;
  /** Short technique label for evidence / report. */
  technique: string;
  /** OWASP Web3 category of the Finding produced by this probe. MUST be one
   * of the three L2 slugs from `owaspWeb3CategorySchema`. */
  category: OwaspWeb3Category;
  /** Default severity if the probe triggers (may be overridden per detection). */
  severity: Severity;
  /** Concise Finding title. */
  title: string;
  /** Indicator-not-verdict description (T-FIX.6 rule). */
  description: string;
  /** User-facing mitigation. */
  recommendation: string;
  /** Evaluate the probe against the loaded target. */
  evaluate(target: Web3DAppTarget): Promise<Web3L2EvaluationResult>;
}

/** Convenience: empty-result with no allocation. */
export const NO_L2_RESULT: Web3L2EvaluationResult = Object.freeze({
  detections: Object.freeze([]),
});

// ── Schema helpers used in tests ────────────────────────────────────────────

export const web3L2DetectionSchema = z.object({
  subjectKey: z.string().optional(),
  rationale: z.string().min(1),
  evidence: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
  severity: z.unknown().optional(),
  description: z.string().optional(),
});

// ── Shared constants / helpers used by the curated probe set ────────────────

/**
 * Tiny curated blocklist of known wallet-drainer / phishing hosts (T-A3.6,
 * `known-bad-domain-reference`). Phase 1 ships with a HAND-PICKED set of
 * public, well-documented wallet-drainer domains (Inferno Drainer, Pink
 * Drainer, Angel Drainer fronts named in public researcher writeups).
 * Expansion lives in a later sprint; the probe is honest about its small
 * surface — it does NOT emit "this isn't a known bad domain" negative
 * findings (silence is silence) AND a hostname not on this list is NOT a
 * statement of safety.
 *
 * Format: lower-cased hostnames (NOT URLs). Matches use exact hostname
 * comparison (case-insensitive), not substring — `safe-wallet-drainer.com`
 * would match `wallet-drainer.com` as a substring, which is a false-positive
 * shape we explicitly avoid.
 */
export const KNOWN_BAD_DOMAIN_LIST: readonly string[] = Object.freeze([
  // Inferno Drainer family — names that appeared in 2023–2024 chainalysis writeups.
  'inferno-drainer.com',
  'inferno-drainer.net',
  'pinkdrainer.com',
  'angeldrainer.app',
  // Wallet-impersonation hosts publicly tracked by community.
  'metarnask.com',
  'metanrask.com',
  'metaamask.io',
  'phantorn.app',
  // Token-impersonation routes commonly named by phishing dashboards.
  'uniswapv4.io',
  'uniswapv4.app',
  'unisswap.org',
]);

/**
 * Hostnames the bundle-drift probe knows how to cross-check against the
 * canonical CDN URL. The probe takes the script's src, recognises one of
 * these hosts, and fetches the SAME URL fresh to compare SHA-256 hashes —
 * a drift means the on-page content differs from what the CDN currently
 * serves at that exact URL (the CDN was compromised, the embed was
 * tampered with, or the page caches a stale version of a mutable URL).
 *
 * Limited to immutable-URL CDNs only: unpkg / jsdelivr / cdnjs pin a
 * specific version in the URL itself. We deliberately do NOT include hosts
 * that serve mutable URLs (raw.githubusercontent.com, cdn.example.com) —
 * a hash mismatch there would be a false-positive shape (the content
 * legitimately changed between page load and probe fetch).
 */
export const BUNDLE_DRIFT_KNOWN_CDN_HOSTS: ReadonlySet<string> = new Set([
  'unpkg.com',
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
]);

/** Truncate a string for inclusion in evidence — mirrors the L1/L3 cap. */
export const EVIDENCE_VALUE_MAX = 400;

export function clipForEvidence(value: string): string {
  if (value.length <= EVIDENCE_VALUE_MAX) return value;
  return `${value.slice(0, EVIDENCE_VALUE_MAX - 3)}...`;
}

/** True iff the resource is the kind that SHOULD carry SRI on a cross-origin
 * embed: a script tag, or a stylesheet `<link rel="stylesheet">`. Mirrors
 * `sriEligible` from the web scan probes — kept local so this module has no
 * dependency on web-probes.ts. */
export function l2SriEligible(tag: string, rel: string | null): boolean {
  if (tag === 'script') return true;
  if (tag === 'link' && rel === 'stylesheet') return true;
  return false;
}

/** Parse a resource URL safely. Returns the parsed URL or `undefined` for
 * invalid / relative / data: / blob: URLs (none of which the probes can
 * meaningfully cross-check). */
export function safeParseUrl(value: string): URL | undefined {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
    return url;
  } catch {
    return undefined;
  }
}

/** True iff `resourceUrl`'s origin differs from `pageUrl`'s origin. Used to
 * scope SRI checks to CROSS-origin embeds — same-origin scripts under the
 * dApp's own control don't carry the same supply-chain risk shape. */
export function isCrossOriginResource(resourceUrl: URL, pageUrl: URL): boolean {
  return resourceUrl.origin !== pageUrl.origin;
}

/**
 * SHA-256 a Uint8Array → lower-case hex string. Pure Node built-in (no
 * dependency). The bundle-drift probe uses this to compare on-page bytes
 * with CDN-served bytes; the integrity-vs-CDN comparison itself stays
 * inside the probe so the helper can be unit-tested independently.
 */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}
