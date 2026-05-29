import { z } from 'zod';

import { scanPaymentInfoSchema } from './payment-api';
import {
  scanJobAiTargetSchema,
  scanJobApiTargetSchema,
  scanJobCrawlBudgetSchema,
  scanJobWeb3TargetSchema,
} from './scan-job';

/**
 * Scan REST API wire contract (T4.1) — the request and response shapes for
 * `POST /scans`, `GET /scans`, `GET /scans/:id`.
 *
 * Lives in `shared` (ARCHITECTURE.md §2 — the home for cross-app contracts) because
 * BOTH `apps/api` (which produces these responses) and `apps/web` (which consumes
 * them) need it, and the two apps must not import each other. This mirrors the SSE
 * event contract (`scan-stream.ts`) and the queue payload (`scan-job.ts`), which
 * already live here for the same reason.
 *
 * IMPORTANT — no BullMQ leak into the browser: web imports this via the
 * `@anthrion/shared/scan-api` SUBPATH, never the package barrel (the barrel re-exports
 * `ScanQueueProducer`, which imports `bullmq`). This module's only runtime dependency
 * is `zod`; `scanJobAiTargetSchema`'s module is likewise zod-only at runtime (its sole
 * `bullmq` reference is a type-only import), so this is safe to bundle into `apps/web`.
 *
 * Wire scan-type casing (`ai-llm-attack` / `web-app-vuln`) and severity casing
 * (`CRITICAL`…) are the over-the-wire values; the api maps to/from its DB enums at the
 * boundary (see `apps/api/.../scan.dto.ts`).
 */

export const scanTypeWireSchema = z.enum(['ai-llm-attack', 'web-app-vuln', 'api-scan', 'web3-dapp']);
export type ScanTypeWire = z.infer<typeof scanTypeWireSchema>;

// ── Report coverage (T6.1 / T6.2) ────────────────────────────────────────────

/**
 * One specific kind of incomplete coverage. The worker writes the same gap kinds it
 * shows in the PDF, so the UI banner and the PDF section stay automatically consistent —
 * single source of truth (T6.2, locked decision: persist coverage on the Scan row).
 *
 * Per-type, NOT a generic 'partial' bucket: a user reading either surface must see
 * WHICH coverage was incomplete (CLAUDE.md §3 honesty).
 */
export const coverageGapKindSchema = z.enum([
  /** AI: target passed Layer 1, but the Layer 2 adaptive attacker did not run at all. */
  'ai-layer2-not-run',
  /** AI: Layer 2 ran but stopped early when it reached its analysis budget. */
  'ai-layer2-budget-exhausted',
  /** AI: some Layer 1 static probes did not execute (e.g. target unreachable for them). */
  'ai-layer1-probes-not-executed',
  /** Web: the target page never loaded, so no probe ran — zero coverage of the target. */
  'web-page-load-failed',
  /** Web: the page loaded but some probes did not execute (timeout/error). */
  'web-probes-not-executed',
  /** API: the baseline reachability check failed; no probe ran. NOT "safe". */
  'api-target-unreachable',
  /** API: some probes did not execute (timeout / internal error). */
  'api-probes-not-executed',
  /** API: raw mode only inspected the single user-supplied endpoint; coverage is shallow by construction. */
  'api-raw-mode-shallow',
  /**
   * Web crawl: the per-scan page-count cap was hit before every in-scope page had been
   * visited (Phase 1.5 Sprint A2). The cap is a HARD ceiling on cost predictability, so
   * unvisited in-scope pages exist but were not scanned — surface as honest partial coverage.
   */
  'crawl-budget-exhausted',
  /**
   * Web crawl: in-scope pages were not explored because robots.txt told us not to (Phase 1.5
   * Sprint A2). Those pages are explicitly off-limits by the target's policy, so the scan
   * could not assess them — never silently elide; mark coverage as partial.
   */
  'crawl-pages-not-explored',
  /**
   * Web crawl (T-FIX.7): crawl mode was selected and the seed loaded, but no additional
   * in-scope links were discovered from it. The crawl ran correctly and is honest about
   * the result, but coverage degraded to single-page — flag explicitly so a multi-page
   * scan that yields single-page coverage never looks identical to a single-page scan.
   */
  'crawl-no-additional-pages-found',
  // ── Web3 dApp scan coverage gap kinds (Sprint A3, T-A3.7) ────────────────────
  /** Web3: the dApp page never loaded — zero coverage of the target, NOT "safe". */
  'web3-page-load-failed',
  /** Web3 L1: synthetic provider captured zero wallet requests — L1 had nothing
   * to inspect. L2/L3 still ran against the loaded page; this gap surfaces the
   * L1-side honesty (NEVER reported as a clean L1 bill). */
  'web3-l1-no-interactive-flow-observed',
  /** Web3 L3: on-chain context provider could not fetch context for ≥1 referenced
   * contract (RPC outage, explorer rate-limit, or operator did not configure
   * WEB3_ALCHEMY_API_KEY / WEB3_ETHERSCAN_API_KEY). Per-address honesty — the
   * report cites the count of unavailable addresses. */
  'web3-l3-on-chain-context-unavailable',
  /** Web3 L3: the operator did not configure both provider keys, so L3 was
   * skipped honestly for every address. Distinct from a provider hiccup so the
   * report's framing names the cause to the operator clearly. */
  'web3-l3-provider-not-configured',
  /** Web3 L2: ≥1 L2 sub-check could not be performed (CDN unreachable for the
   * bundle-drift check, TLS details not surfaced by the browser, DNSSEC validation
   * out-of-scope). Per-probe honesty — the count of coverage notes is surfaced. */
  'web3-l2-subchecks-skipped',
  /** Web3: ≥1 layer of the three-layer scan had a probe that did not execute
   * (timeout/error). Mirrors the api / web "probes-not-executed" gap kind at
   * the scan-wide level. */
  'web3-layer-probes-not-executed',
]);
export type CoverageGapKind = z.infer<typeof coverageGapKindSchema>;

export const coverageGapSchema = z.object({
  kind: coverageGapKindSchema,
  title: z.string().min(1),
  detail: z.string().min(1),
});
export type CoverageGap = z.infer<typeof coverageGapSchema>;

/**
 * Per-scan coverage summary persisted on the `Scan` row (T6.2) and surfaced by the api
 * on the scan detail. `complete: true` AND `gaps: []` means the engine reported full
 * coverage. `complete: false` carries the specific gap(s).
 *
 * NULL on the wire means "unknown" — a scan whose report was never generated (FAILED,
 * or report generation itself failed) or a legacy pre-T6.2 row. The UI MUST treat null
 * as neutral, never as a claim of completeness.
 */
export const reportCoverageSchema = z.object({
  complete: z.boolean(),
  gaps: z.array(coverageGapSchema),
});
export type ReportCoverage = z.infer<typeof reportCoverageSchema>;

export const scanStatusWireSchema = z.enum(['QUEUED', 'RUNNING', 'DONE', 'FAILED']);
export type ScanStatusWire = z.infer<typeof scanStatusWireSchema>;

export const findingSeverityWireSchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export type FindingSeverityWire = z.infer<typeof findingSeverityWireSchema>;

// ── Request: POST /scans ─────────────────────────────────────────────────────

/**
 * Create-scan request body: scan type + target. No `scanId` — the server creates the
 * `Scan` record and owns its id. AI target shapes are REUSED from `scanJobAiTargetSchema`
 * so the request contract cannot drift from the queue payload. For AI endpoint targets
 * the body MAY carry auth, forwarded to the worker but NEVER persisted (CLAUDE.md §7).
 */
export const createScanRequestSchema = z.discriminatedUnion('scanType', [
  z.object({ scanType: z.literal('ai-llm-attack'), target: scanJobAiTargetSchema }),
  z.object({
    scanType: z.literal('web-app-vuln'),
    target: z.object({ url: z.string().url() }),
    // Sprint A2: optional crawl budget. Absent → single-page (Phase 1 behavior).
    crawl: scanJobCrawlBudgetSchema.optional(),
  }),
  z.object({ scanType: z.literal('api-scan'), target: scanJobApiTargetSchema }),
  // Sprint A3 (T-A3.7): Web3 dApp scan — URL + chain (ethereum/base).
  // Wallet-interaction depth + timeouts are engine defaults applied worker-side.
  z.object({ scanType: z.literal('web3-dapp'), target: scanJobWeb3TargetSchema }),
]);
export type CreateScanRequest = z.infer<typeof createScanRequestSchema>;

// ── Responses ────────────────────────────────────────────────────────────────

export const createScanResponseSchema = z.object({
  scanId: z.string(),
  status: scanStatusWireSchema,
  scanType: scanTypeWireSchema,
  createdAt: z.string(),
});
export type CreateScanResponse = z.infer<typeof createScanResponseSchema>;

/** A single finding as returned to clients. Internal columns (e.g. userId) are not exposed. */
export const findingResponseSchema = z.object({
  id: z.string(),
  severity: findingSeverityWireSchema,
  category: z.string(),
  title: z.string(),
  description: z.string(),
  evidence: z.object({
    input: z.string(),
    output: z.string(),
    metadata: z.record(z.string(), z.string()).optional(),
  }),
  recommendation: z.string(),
});
export type FindingResponse = z.infer<typeof findingResponseSchema>;

export const scanDetailResponseSchema = z.object({
  id: z.string(),
  status: scanStatusWireSchema,
  scanType: scanTypeWireSchema,
  targetUrl: z.string().nullable(),
  targetKind: z.string().nullable(),
  failureReason: z.string().nullable(),
  createdAt: z.string(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  // How this scan was paid for (T5.4 Part 1) — kind + status only, no on-chain payload
  // (CLAUDE.md §7). Nullable: a scan can briefly exist without a linked payment.
  payment: scanPaymentInfoSchema.nullable(),
  // Whether a downloadable PDF security report artifact exists for this scan (T6.1). The
  // UI shows the download action only when true — never a broken button (FAILED scans and
  // scans whose report generation failed are false). Downloaded via GET /scans/:id/report.
  reportAvailable: z.boolean(),
  // Coverage summary the engine reported when the PDF was generated (T6.2). NULL means
  // unknown — pre-T6.2 scans, FAILED scans, and scans whose report generation never ran.
  // The UI MUST render null as neutral, never as "complete" (CLAUDE.md §3 honesty).
  reportCoverage: reportCoverageSchema.nullable(),
  findings: z.array(findingResponseSchema),
});
export type ScanDetailResponse = z.infer<typeof scanDetailResponseSchema>;

export const scanSummaryResponseSchema = z.object({
  id: z.string(),
  status: scanStatusWireSchema,
  scanType: scanTypeWireSchema,
  targetUrl: z.string().nullable(),
  createdAt: z.string(),
  finishedAt: z.string().nullable(),
});
export type ScanSummaryResponse = z.infer<typeof scanSummaryResponseSchema>;

export const scanListResponseSchema = z.object({
  scans: z.array(scanSummaryResponseSchema),
});
export type ScanListResponse = z.infer<typeof scanListResponseSchema>;
