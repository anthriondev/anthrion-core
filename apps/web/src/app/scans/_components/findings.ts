import type { FindingResponse, FindingSeverityWire } from '@anthrion/shared/scan-api';
import type { Severity } from '@anthrion/ui';

/**
 * Findings report helpers (T4.4).
 *
 * Severity casing is mapped HERE, at the data boundary — where `getScan` data enters
 * the report UI. The API returns wire-cased severities (`HIGH`, `CRITICAL`, …, the DB
 * `FindingSeverity` enum); the `Badge` component (T4.3a) uses `High`/`Critical`/….
 *
 * Unknown severities never reach this mapping: `getScan` validates the response with
 * `findingResponseSchema` (Zod, in `@anthrion/shared`), so a severity outside the five
 * known values is rejected at the api-client boundary as a clear `invalid-response`
 * error rather than silently passed through (CLAUDE.md §3). The map below is therefore
 * exhaustive over the validated union — no `as`, no silent fallback.
 */
const WIRE_TO_BADGE: Record<FindingSeverityWire, Severity> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

export function toBadgeSeverity(wire: FindingSeverityWire): Severity {
  return WIRE_TO_BADGE[wire];
}

/** Display rank, most severe first (matches `SEVERITIES` order from packages/ui). */
const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

export type SeverityCounts = Record<Severity, number>;

/** Count findings per severity (all five levels present, zero-filled). */
export function countBySeverity(findings: FindingResponse[]): SeverityCounts {
  const counts: SeverityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const finding of findings) {
    counts[toBadgeSeverity(finding.severity)] += 1;
  }
  return counts;
}

/**
 * Sort findings most-severe first. `Array.prototype.sort` is stable, so findings with
 * the same severity keep their API order.
 */
export function sortFindings(findings: FindingResponse[]): FindingResponse[] {
  return [...findings].sort(
    (a, b) => SEVERITY_RANK[toBadgeSeverity(a.severity)] - SEVERITY_RANK[toBadgeSeverity(b.severity)],
  );
}

/**
 * Web3 finding-layer attribution (Sprint A3, T-A3.8). Maps an OWASP Web3
 * category slug to the layer that emitted it. Used by the scan detail view
 * to render the three sections separately — and by the PDF template for the
 * same partitioning.
 *
 * Kept local (small static set; no scan-engine dependency from the web app).
 * Each L1 / L2 / L3 slug list mirrors `owaspWeb3CategorySchema`'s blocks
 * exactly; the aggregate `elevated-risk-contract` slug is grouped under L3
 * since it is composed from L3 indicator findings. Drift between this list
 * and the engine enum is caught by `web3-finding-layer.test.ts` — the test
 * loads the wire schema and asserts every Web3 slug is mapped to a layer.
 */
const WEB3_L1_SLUGS: ReadonlySet<string> = new Set([
  'wallet-approval-phishing',
  'deceptive-typed-data-signature',
  'personal-sign-payload-smell',
  'eip-7702-set-code-delegation',
  'mismatched-chainid-request',
  'permit2-mass-approval',
]);

const WEB3_L2_SLUGS: ReadonlySet<string> = new Set([
  'dapp-frontend-integrity',
  'known-bad-domain-reference',
  'dapp-dns-or-tls-hygiene',
]);

const WEB3_L3_SLUGS: ReadonlySet<string> = new Set([
  'contract-source-not-verified',
  'proxy-without-verified-implementation',
  'eoa-admin-single-key',
  'recent-contract-deployment',
  'token-impersonation-indicator',
  'elevated-risk-contract', // aggregate — composed from L3 indicators, rendered with L3.
]);

export type Web3FindingLayer = 'l1' | 'l2' | 'l3' | 'unknown';

/** Return which Web3 layer a finding belongs to, based on its category slug.
 * Returns `'unknown'` for slugs that aren't part of the Web3 taxonomy (e.g.
 * if a stray finding from another scan type ever lands on a web3-dapp
 * report — never expected, but rendered honestly rather than dropped). */
export function web3FindingLayer(category: string): Web3FindingLayer {
  if (WEB3_L1_SLUGS.has(category)) return 'l1';
  if (WEB3_L2_SLUGS.has(category)) return 'l2';
  if (WEB3_L3_SLUGS.has(category)) return 'l3';
  return 'unknown';
}

/** Partition findings into the three Web3 layers + an `unknown` bucket. */
export interface Web3FindingPartition {
  l1: FindingResponse[];
  l2: FindingResponse[];
  l3: FindingResponse[];
  unknown: FindingResponse[];
}

export function partitionWeb3Findings(findings: FindingResponse[]): Web3FindingPartition {
  const out: Web3FindingPartition = { l1: [], l2: [], l3: [], unknown: [] };
  for (const finding of findings) {
    out[web3FindingLayer(finding.category)].push(finding);
  }
  return out;
}

/** Stable single-source-of-truth lists of slugs per layer, exported for tests
 * (so a drift check can compare against the engine enum). */
export const WEB3_LAYER_SLUGS = {
  l1: WEB3_L1_SLUGS,
  l2: WEB3_L2_SLUGS,
  l3: WEB3_L3_SLUGS,
} as const;
