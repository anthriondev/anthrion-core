import { z } from 'zod';

import type { Finding, Severity } from '@anthrion/scan-engine';
import type { ScanReport } from '@anthrion/sandbox-runtime';
import { coverageGapKindSchema, coverageGapSchema, reportCoverageSchema, type CoverageGap, type CoverageGapKind } from '@anthrion/shared';

/**
 * Normalised PDF-report model (T6.1) — the single, self-contained structure the report
 * template renders. It is deliberately decoupled from the engine types so the template
 * is a pure unit: it takes THIS model and produces HTML, nothing else.
 *
 * Trust boundary (CLAUDE.md §3): scan results crossing into the report are treated as
 * data to validate. `buildReportModel` assembles the model from the worker's scan
 * result + scan metadata and `reportModelSchema.parse`s it before it reaches the
 * template — a malformed model fails loudly here rather than producing a broken PDF.
 *
 * Disclosure (CLAUDE.md §7): the PDF may be shared publicly, so this model carries ONLY
 * product-capability / findings / recommendation text. It never includes our LLM model
 * names, infra/cloud details, server IPs, raw token budgets, or worker/sandbox
 * internals. In particular the engine `Finding.evidence.metadata` map (which can echo
 * the *target's* model name via `target_model`, see endpoint-adapter.ts) is NOT carried
 * into the report — only the input/output evidence and the human-readable fields are.
 */

/** Severity scale, most-severe first. Matches the engine `Severity` casing 1:1. */
export const reportSeverityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;
export const reportSeveritySchema = z.enum(reportSeverityOrder);
export type ReportSeverity = z.infer<typeof reportSeveritySchema>;

/** A single finding as shown in the PDF — no raw metadata map (see §7 note above). */
export const reportFindingSchema = z.object({
  severity: reportSeveritySchema,
  category: z.string().min(1),
  title: z.string().min(1),
  description: z.string().min(1),
  /** The attack/probe that was sent (engine `evidence.input`), truncated for print. */
  evidenceInput: z.string(),
  /** The target's response (engine `evidence.output`), truncated for print. */
  evidenceOutput: z.string(),
  recommendation: z.string().min(1),
});
export type ReportFinding = z.infer<typeof reportFindingSchema>;

/**
 * Coverage gap schemas now live in `@anthrion/shared/scan-api` (T6.2 — single source of
 * truth: the worker writes the same coverage summary to the Scan row that it puts in the
 * PDF, so the UI banner and the PDF section stay automatically consistent). Re-exported
 * here so existing call sites importing from the report module keep compiling.
 */
export { coverageGapKindSchema, coverageGapSchema, type CoverageGap, type CoverageGapKind };

export const reportSeverityCountsSchema = z.object({
  Critical: z.number().int().nonnegative(),
  High: z.number().int().nonnegative(),
  Medium: z.number().int().nonnegative(),
  Low: z.number().int().nonnegative(),
  Info: z.number().int().nonnegative(),
});
export type ReportSeverityCounts = z.infer<typeof reportSeverityCountsSchema>;

export const reportScanTypeSchema = z.enum(['ai-llm-attack', 'web-app-vuln', 'api-scan', 'web3-dapp']);
export type ReportScanType = z.infer<typeof reportScanTypeSchema>;

export const reportModelSchema = z.object({
  scanId: z.string().min(1),
  scanType: reportScanTypeSchema,
  /** Human label for the scan type, e.g. "AI / LLM attack scan". */
  scanTypeLabel: z.string().min(1),
  /**
   * Safe description of what was scanned. For AI system-prompt targets this is a generic
   * phrase, never the raw prompt (which is sensitive and not stored anyway, §7).
   */
  targetDescription: z.string().min(1),
  /** For AI scans: "Endpoint" | "System prompt". Null for web scans. */
  targetMode: z.string().nullable(),
  /** ISO timestamps; started/finished may be null if the scan row lacked them. */
  generatedAt: z.string().min(1),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  severityCounts: reportSeverityCountsSchema,
  findings: z.array(reportFindingSchema),
  /** Coverage summary — the exact value persisted on `Scan.reportCoverage` (T6.2). */
  coverage: reportCoverageSchema,
});
export type ReportModel = z.infer<typeof reportModelSchema>;

// ── Builder ──────────────────────────────────────────────────────────────────

/** Scan metadata the report needs, read from the persisted `Scan` row (authoritative). */
export interface ReportScanMeta {
  scanId: string;
  targetUrl: string | null;
  targetKind: string | null;
  startedAt: Date | null;
  finishedAt: Date | null;
}

export interface BuildReportModelInput {
  meta: ReportScanMeta;
  findings: readonly Finding[];
  report: ScanReport;
  /** When the report was generated (defaults to now). */
  generatedAt?: Date;
}

/** Max evidence length carried into the PDF — keeps the layout readable; the full
 * transcript lives in the SCAN_LOG artifact. The engine already truncates output. */
const EVIDENCE_MAX = 1500;

/**
 * Build and validate the report model from a successful scan's result + metadata.
 * Throws (via Zod) if the assembled model is malformed — the caller treats report
 * generation as best-effort and logs the failure without failing the scan (T6.1).
 */
export function buildReportModel(input: BuildReportModelInput): ReportModel {
  const { meta, findings, report } = input;
  const generatedAt = input.generatedAt ?? new Date();

  const model = {
    scanId: meta.scanId,
    scanType: report.scanType,
    scanTypeLabel: scanTypeLabel(report.scanType),
    targetDescription: describeTarget(report.scanType, meta.targetUrl, meta.targetKind),
    targetMode: targetMode(report.scanType, meta.targetKind),
    generatedAt: generatedAt.toISOString(),
    startedAt: meta.startedAt?.toISOString() ?? null,
    finishedAt: meta.finishedAt?.toISOString() ?? null,
    severityCounts: countBySeverity(findings),
    findings: sortBySeverity(findings).map(toReportFinding),
    coverage: buildCoverage(report),
  } satisfies ReportModel;

  // Validate at the template boundary (CLAUDE.md §3) before returning.
  return reportModelSchema.parse(model);
}

function scanTypeLabel(scanType: ReportScanType): string {
  if (scanType === 'ai-llm-attack') return 'AI / LLM attack scan';
  if (scanType === 'web-app-vuln') return 'Web application vulnerability scan';
  if (scanType === 'api-scan') return 'API security scan';
  return 'Web3 dApp scan';
}

/** Safe target description — never leaks a raw pasted system prompt (§7). */
function describeTarget(scanType: ReportScanType, targetUrl: string | null, targetKind: string | null): string {
  if (scanType === 'web-app-vuln') {
    return targetUrl ?? 'Web application';
  }
  if (scanType === 'api-scan') {
    if (targetKind === 'api-spec') {
      // Spec mode may or may not have a baseUrl persisted; either way, never echo the
      // raw spec document into the public report (§7 — same posture as system prompts).
      return targetUrl !== null ? `API (spec): ${targetUrl}` : 'API (OpenAPI/Swagger spec)';
    }
    return targetUrl ?? 'API endpoint';
  }
  if (scanType === 'web3-dapp') {
    // targetKind = 'web3-ethereum' | 'web3-base' (set by api describeTarget); strip
    // the prefix and append for a readable summary. Never echo wallet/key fields —
    // by construction the web3-dapp wire surface carries none.
    const chain = targetKind?.startsWith('web3-') === true ? targetKind.slice('web3-'.length) : null;
    return targetUrl !== null
      ? chain !== null
        ? `dApp (${chain}): ${targetUrl}`
        : `dApp: ${targetUrl}`
      : 'Web3 dApp';
  }
  if (targetKind === 'system-prompt') {
    return 'System prompt (provided inline)';
  }
  return targetUrl ?? 'AI agent endpoint';
}

function targetMode(scanType: ReportScanType, targetKind: string | null): string | null {
  if (scanType === 'ai-llm-attack') {
    return targetKind === 'system-prompt' ? 'System prompt' : 'Endpoint';
  }
  if (scanType === 'api-scan') {
    return targetKind === 'api-spec' ? 'OpenAPI/Swagger spec' : 'Raw endpoint';
  }
  if (scanType === 'web3-dapp') {
    if (targetKind === 'web3-ethereum') return 'Ethereum mainnet';
    if (targetKind === 'web3-base') return 'Base mainnet';
    return 'Web3 dApp';
  }
  return null;
}

/** Display rank, most-severe first — matches `reportSeverityOrder`. */
const SEVERITY_RANK: Record<ReportSeverity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

/** Sort findings most-severe first; stable, so same-severity order is preserved. */
function sortBySeverity(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

function countBySeverity(findings: readonly Finding[]): ReportSeverityCounts {
  const counts: ReportSeverityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

function toReportFinding(finding: Finding): ReportFinding {
  return {
    // Engine severity is already Title-case (`Severity`), identical to ReportSeverity.
    severity: finding.severity satisfies Severity,
    category: finding.category,
    title: finding.title,
    description: finding.description,
    evidenceInput: truncate(finding.evidence.input, EVIDENCE_MAX),
    evidenceOutput: truncate(finding.evidence.output, EVIDENCE_MAX),
    recommendation: finding.recommendation,
  };
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/**
 * Web3 finding-layer attribution (Sprint A3, T-A3.8). Maps an OWASP Web3
 * category slug to the layer that emitted it — mirror of the web-side
 * `web3FindingLayer` in apps/web/.../findings.ts. Kept local so the worker
 * has no cross-app coupling; the two lists stay in sync with the engine
 * enum (drift check in report-model.test.ts).
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
  'elevated-risk-contract', // aggregate, rendered with L3.
]);

export type Web3FindingLayer = 'l1' | 'l2' | 'l3' | 'unknown';

export function web3FindingLayer(category: string): Web3FindingLayer {
  if (WEB3_L1_SLUGS.has(category)) return 'l1';
  if (WEB3_L2_SLUGS.has(category)) return 'l2';
  if (WEB3_L3_SLUGS.has(category)) return 'l3';
  return 'unknown';
}

export interface Web3FindingPartition {
  l1: ReportFinding[];
  l2: ReportFinding[];
  l3: ReportFinding[];
  unknown: ReportFinding[];
}

export function partitionWeb3ReportFindings(findings: readonly ReportFinding[]): Web3FindingPartition {
  const out: Web3FindingPartition = { l1: [], l2: [], l3: [], unknown: [] };
  for (const finding of findings) {
    out[web3FindingLayer(finding.category)].push(finding);
  }
  return out;
}

/** Single source of truth for the slug lists, exported for the drift test. */
export const WEB3_LAYER_SLUGS = {
  l1: WEB3_L1_SLUGS,
  l2: WEB3_L2_SLUGS,
  l3: WEB3_L3_SLUGS,
} as const;

/**
 * Derive the per-type coverage gaps from the engine report (the locked-decision honesty
 * rule, Option 1: any incomplete coverage gets a marker, specific to its kind).
 *
 * Note on what is detectable: the engine's WIRE report exposes layer/coverage outcomes
 * but NOT per-category Layer-2 errors, so Layer-2 incompleteness is surfaced via
 * `layer2Ran` / `layer2StoppedReason`. A scan where Layer 1 caught issues and Layer 2
 * was correctly gated out (`passedLayer1 === false`) is NOT a gap — that is complete
 * coverage at the appropriate depth.
 */
function buildCoverage(report: ScanReport): ReportModel['coverage'] {
  const gaps: CoverageGap[] = [];

  if (report.scanType === 'ai-llm-attack') {
    if (report.layer1Stats.notExecuted > 0) {
      gaps.push({
        kind: 'ai-layer1-probes-not-executed',
        title: 'Some static probes did not execute',
        detail:
          `${report.layer1Stats.notExecuted} of ${report.layer1Stats.total} Layer 1 static probe(s) did not run ` +
          '(for example, the target could not be reached for those checks). Those attack classes were not assessed.',
      });
    }
    // Layer 2 only matters when the target passed Layer 1 (it is gated otherwise).
    if (report.passedLayer1) {
      if (!report.layer2Ran) {
        gaps.push({
          kind: 'ai-layer2-not-run',
          title: 'Layer 2 adaptive testing did not run',
          detail:
            'The target passed Layer 1 static probing, but the Layer 2 adaptive attacker did not run. ' +
            'Deeper, adaptive attack coverage is incomplete for this scan.',
        });
      } else if (report.layer2StoppedReason === 'budget-exhausted') {
        gaps.push({
          kind: 'ai-layer2-budget-exhausted',
          title: 'Layer 2 adaptive testing stopped early',
          detail:
            'The Layer 2 adaptive attacker reached its analysis budget before exploring every attack category. ' +
            'Adaptive attack coverage is incomplete — categories beyond the budget were not assessed.',
        });
      }
    }
  } else if (report.scanType === 'web-app-vuln') {
    if (!report.pageLoaded) {
      gaps.push({
        kind: 'web-page-load-failed',
        title: 'Target page could not be loaded',
        detail:
          'The target page failed to load, so no vulnerability probe could run. This report reflects ' +
          'NO coverage of the target — a failed load is not a clean result.',
      });
    } else if (report.stats.notExecuted > 0) {
      gaps.push({
        kind: 'web-probes-not-executed',
        title: 'Some probes did not execute',
        detail:
          `${report.stats.notExecuted} of ${report.stats.total} probe(s) did not execute (timeout or error). ` +
          'Those checks were not completed, so coverage is incomplete.',
      });
    }
    // Crawl-specific gaps (Phase 1.5 Sprint A2). Independent of per-page probe gaps:
    // a crawl with every probe green can STILL be partial if the page-count budget cut
    // off discovery or robots.txt blocked discovered URLs. Both gaps surface the
    // exact counts so the reader can decide whether to widen the budget.
    if (report.crawl !== undefined) {
      const crawl = report.crawl;
      if (crawl.stopReason === 'budget-exhausted') {
        gaps.push({
          kind: 'crawl-budget-exhausted',
          title: 'Crawl page-count limit was reached',
          detail:
            `The crawl hit its hard page-count limit of ${crawl.budget.maxPages} ` +
            `(${crawl.pagesVisited} visited) before every in-scope page was discovered. ` +
            `${crawl.unvisitedDiscoveredCount} additional in-scope URL(s) were found but not scanned, ` +
            'so coverage is partial. Increase the page-count budget on a future scan to widen coverage.',
        });
      }
      if (crawl.robotsBlockedCount > 0) {
        gaps.push({
          kind: 'crawl-pages-not-explored',
          title: 'Some pages were blocked by robots.txt',
          detail:
            `${crawl.robotsBlockedCount} in-scope URL(s) were not scanned because the target's ` +
            'robots.txt disallows them. Those pages were not assessed — coverage is partial by ' +
            "the target's own policy.",
        });
      }
      // T-FIX.7: crawl mode selected, seed loaded, queue completed naturally, no
      // robots-blocking, no budget exhaustion — yet only the seed was visited. The
      // user asked for multi-page coverage and got single-page; surface it instead
      // of letting the report look identical to a single-page scan. Common cause is
      // an SPA shell with all routing rendered client-side (e.g. Juice Shop).
      if (
        crawl.stopReason === 'completed' &&
        crawl.pagesVisited <= 1 &&
        crawl.robotsBlockedCount === 0 &&
        report.pageLoaded
      ) {
        gaps.push({
          kind: 'crawl-no-additional-pages-found',
          title: 'Crawl found no additional in-scope pages',
          detail:
            'Multi-page crawl mode was selected, but no additional in-scope links were ' +
            'discovered from the start URL. The target may be a single-page app, or links ' +
            'may be rendered client-side after load. Findings are limited to the start URL.',
        });
      }
    }
  } else if (report.scanType === 'api-scan') {
    // API scan (Phase 1.5 Sprint A1, T-A1.3). Same honesty rule: target-unreachable
    // is NEVER a clean bill; raw-mode coverage is shallow by construction and the
    // report surfaces that so the user sees it.
    if (report.outcome === 'target-unreachable') {
      gaps.push({
        kind: 'api-target-unreachable',
        title: 'Target API could not be reached',
        detail:
          'The baseline reachability check against the target API did not succeed, so no probe ' +
          'meaningfully ran. This report reflects NO coverage of the target — an unreachable ' +
          'API is not a clean result.',
      });
    } else if (report.stats.notExecuted > 0) {
      gaps.push({
        kind: 'api-probes-not-executed',
        title: 'Some API probes did not execute',
        detail:
          `${report.stats.notExecuted} of ${report.stats.total} probe(s) did not execute (timeout or error). ` +
          'Those checks were not completed, so coverage is incomplete.',
      });
    }
    if (report.coverage === 'raw') {
      gaps.push({
        kind: 'api-raw-mode-shallow',
        title: 'Raw mode — coverage limited to one endpoint',
        detail:
          'The scan ran in raw mode against a single endpoint URL, so only that one operation ' +
          'was probed. Endpoint enumeration is shallow by construction; vulnerabilities elsewhere ' +
          'in the API were not assessed. Provide an OpenAPI/Swagger spec for full coverage.',
      });
    }
  } else {
    // Web3 dApp scan (Phase 1.5 Sprint A3, T-A3.7). Same honesty rules: every layer
    // can incompletely cover, and the report surfaces WHICH layer was incomplete.
    if (!report.pageLoaded) {
      gaps.push({
        kind: 'web3-page-load-failed',
        title: 'dApp page could not be loaded',
        detail:
          'The dApp page failed to load, so no L1 / L2 / L3 probe could run. This report reflects ' +
          'NO coverage of the target — a failed load is not a clean result.',
      });
    } else {
      if (!report.observedInteractiveFlow) {
        gaps.push({
          kind: 'web3-l1-no-interactive-flow-observed',
          title: 'L1 captured no wallet interaction',
          detail:
            'The synthetic EIP-1193 provider captured zero wallet requests during the L1 ' +
            'observation window — either the dApp gates wallet calls behind a Connect button ' +
            'we did not drive, or the dApp does not interact with a wallet at all. L1 ' +
            'indicators (approval phishing, typed-data smell, EIP-7702 SetCode, chain-id ' +
            'mismatch, Permit2) could not be assessed. L2 / L3 still ran.',
        });
      }
      const layerProbesNotExecuted =
        report.l1Stats.notExecuted > 0 || report.l2Stats.notExecuted > 0 || report.l3Stats.notExecuted > 0;
      if (layerProbesNotExecuted) {
        gaps.push({
          kind: 'web3-layer-probes-not-executed',
          title: 'Some L1 / L2 / L3 probes did not execute',
          detail:
            `L1 ${report.l1Stats.notExecuted}/${report.l1Stats.total} not-executed; ` +
            `L2 ${report.l2Stats.notExecuted}/${report.l2Stats.total} not-executed; ` +
            `L3 ${report.l3Stats.notExecuted}/${report.l3Stats.total} not-executed. ` +
            'Those checks were not completed (timeout or error), so coverage is incomplete.',
        });
      }
      if (!report.l3ProviderConfigured) {
        gaps.push({
          kind: 'web3-l3-provider-not-configured',
          title: 'L3 on-chain provider not configured',
          detail:
            'The operator did not configure both WEB3_ALCHEMY_API_KEY and WEB3_ETHERSCAN_API_KEY, ' +
            'so L3 on-chain context (verified source, proxy implementation, admin role surface, ' +
            'deployment age) was honestly skipped for every referenced contract. L1 / L2 ran as ' +
            'normal — but the L3 indicators are absent from this report by configuration, not by ' +
            'the contracts being clean.',
        });
      } else if (report.l3Stats.unavailableAddressCount > 0) {
        gaps.push({
          kind: 'web3-l3-on-chain-context-unavailable',
          title: 'L3 context unavailable for some contracts',
          detail:
            `${report.l3Stats.unavailableAddressCount} of ${report.l3Stats.addressCount} referenced ` +
            'contract(s) could not have their on-chain context fetched (RPC outage, explorer ' +
            'rate-limit, or per-address provider error). L3 indicators were not assessed for ' +
            'those addresses; the rest of the scan ran normally.',
        });
      }
      if (report.l2Stats.coverageNoteCount > 0) {
        gaps.push({
          kind: 'web3-l2-subchecks-skipped',
          title: 'Some L2 sub-checks were skipped honestly',
          detail:
            `${report.l2Stats.coverageNoteCount} L2 sub-check(s) could not be performed in this ` +
            'scan (CDN unreachable for bundle-drift cross-check, browser did not surface TLS ' +
            'details, DNSSEC validation out-of-scope for the Phase 1 hand-rolled probe). The ' +
            'sub-check is honestly skipped — never reported as a clean pass.',
        });
      }
    }
  }

  return { complete: gaps.length === 0, gaps };
}
