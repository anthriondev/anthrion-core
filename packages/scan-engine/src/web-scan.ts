import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';

import type { OwaspWebCategory } from './category';
import type { WebAppVulnScanConfig, WebScanTimeouts } from './config';
import { findingSchema, type Evidence, type Finding } from './finding';
import { emitProgress, type ScanProgressCallback } from './progress';
import { PlaywrightPageContext } from './web-page-context';
import type { PageContext, WebDetection, WebProbe } from './web-probe';
import { WEB_PROBES } from './web-probes';

/**
 * Web app vulnerability scan — single-page DAST runner (T2.6).
 *
 * Two layers:
 *  - `scanSinglePage(page, url, …)` — the reusable UNIT (Context §1): scan exactly
 *    ONE URL with an already-open Playwright `Page`. Phase 1.5 crawl will create
 *    one browser/context and call this per discovered URL — adding a
 *    discover-pages → scan-each layer ON TOP, without rebuilding it. The unit is
 *    self-contained and browser-lifecycle-agnostic (it does not launch or close
 *    the browser).
 *  - `runWebAppScan(config, …)` — entry point that owns the browser lifecycle:
 *    launch headless Chromium, scan the single configured URL, always tear down.
 *
 * Honesty rules (Context §3, mirroring T2.3):
 *  - A page that fails to load is NOT "safe": every probe is `not-executed` and the
 *    outcome is `page-load-failed`.
 *  - A probe that hits its timeout (or errors) is `not-executed`, never `clean`.
 *    Consumers see incomplete coverage via `stats.notExecuted` / outcome.
 *
 * Each `Finding` is Zod-validated before leaving the engine (ARCHITECTURE.md §4.4).
 */

/** Status of a single probe run against a loaded page. */
export type WebProbeStatus = 'detected' | 'clean' | 'not-executed';

export interface WebProbeResult {
  probeId: string;
  technique: string;
  category: OwaspWebCategory;
  status: WebProbeStatus;
  /** Explanation of the decision, or the reason the probe did not execute. */
  rationale: string;
  /** Normalised finding — present iff `status === 'detected'`. */
  finding?: Finding;
  /** Error/timeout message — present iff `status === 'not-executed'`. */
  error?: string;
}

/**
 * Summary outcome of a single-page web scan:
 * - `vulnerable`        — ≥1 probe detected an issue.
 * - `passed`           — all probes executed, zero findings.
 * - `passed-with-gaps` — no findings, but ≥1 probe did not execute (timeout/error):
 *                        coverage is incomplete, so this is NOT a clean bill.
 * - `page-load-failed` — the page could not be loaded; no probe ran. NOT "safe".
 */
export type WebScanOutcome = 'vulnerable' | 'passed' | 'passed-with-gaps' | 'page-load-failed';

export interface WebScanStats {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
}

/** Result of scanning ONE page. (Phase 1.5 crawl will collect many of these.) */
export interface WebPageScanResult {
  /** URL requested by the scan. */
  url: string;
  /** Final URL after redirects — present iff the page loaded. */
  finalUrl?: string;
  /** True if the main document loaded and probes could run. */
  pageLoaded: boolean;
  /** HTTP status of the main response — present iff the page loaded. */
  httpStatus?: number;
  /** Reason the page failed to load — present iff `pageLoaded === false`. */
  loadError?: string;
  outcome: WebScanOutcome;
  findings: Finding[];
  results: WebProbeResult[];
  stats: WebScanStats;
}

/** Page-load completion event. `domcontentloaded` is robust against pages that never fire `load`. */
export type WaitUntil = 'load' | 'domcontentloaded' | 'networkidle' | 'commit';

export interface ScanSinglePageOptions {
  /** Resolved per-operation timeouts (from `ScanConfig`). */
  timeouts: WebScanTimeouts;
  /** Probe set to run. Defaults to `WEB_PROBES`. */
  probes?: readonly WebProbe[];
  /** Navigation completion event. Defaults to `domcontentloaded`. */
  waitUntil?: WaitUntil;
  /** Optional stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

/** Default Chromium launch args. Isolation comes from the Docker sandbox (T3.2),
 * not Chromium's in-process sandbox — disabling it is the standard pattern when
 * the browser already runs inside a locked-down container (and is required when
 * running as root). See the T3.2 note in the task report. */
export const DEFAULT_LAUNCH_ARGS: readonly string[] = ['--no-sandbox', '--disable-dev-shm-usage'];

/** Error used to mark a probe that exceeded its per-probe timeout. */
export class ProbeTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProbeTimeoutError';
  }
}

/**
 * Run `op`, rejecting with `ProbeTimeoutError` if it does not settle within `ms`.
 * The timeout is a GUARD for a hung browser round-trip; it does not cancel the
 * underlying Chromium call (a memoized result may still serve the next probe).
 */
function withTimeout<T>(ms: number, label: string, op: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new ProbeTimeoutError(`${label} did not finish within ${ms}ms (timeout guard)`));
    }, ms);
    timer.unref();
    op.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

/** Maximum length of `evidence.output` to keep findings size-bounded. */
const EVIDENCE_OUTPUT_MAX = 4_000;

function buildFinding(probe: WebProbe, detection: WebDetection, ctx: PageContext): Finding {
  const rawOutput = detection.evidence ?? detection.rationale;
  const output =
    rawOutput.length > EVIDENCE_OUTPUT_MAX ? `${rawOutput.slice(0, EVIDENCE_OUTPUT_MAX)}…` : rawOutput;

  const metadata: Record<string, string> = {
    probeId: probe.id,
    technique: probe.technique,
    requestedUrl: ctx.requestedUrl,
    httpStatus: String(ctx.status),
    detection: detection.rationale,
  };
  if (detection.metadata !== undefined) {
    for (const [key, value] of Object.entries(detection.metadata)) {
      metadata[key] = value;
    }
  }

  const evidence: Evidence = {
    input: `GET ${ctx.finalUrl}`,
    output,
    metadata,
  };

  return findingSchema.parse({
    id: `web:${probe.id}`,
    severity: detection.severity ?? probe.severity,
    category: probe.category,
    title: probe.title,
    description: probe.description,
    evidence,
    recommendation: probe.recommendation,
  });
}

/**
 * Scan exactly ONE page (the reusable unit, Context §1). The caller owns the
 * `Page`'s browser/context — this function only navigates, observes, and runs
 * probes. It never throws for an unreachable target or a timed-out probe; those
 * become honest `page-load-failed` / `not-executed` results.
 */
export async function scanSinglePage(
  page: Page,
  url: string,
  options: ScanSinglePageOptions,
): Promise<WebPageScanResult> {
  const probes = options.probes ?? WEB_PROBES;
  const waitUntil = options.waitUntil ?? 'domcontentloaded';
  const { navigationMs, probeMs } = options.timeouts;
  const onProgress = options.onProgress;

  // --- Operation 1: navigation (its own timeout). -------------------------
  emitProgress(onProgress, { phase: 'web-load', status: 'started', message: `Loading ${url}` });
  let response;
  try {
    response = await page.goto(url, { timeout: navigationMs, waitUntil });
  } catch (error) {
    emitProgress(onProgress, {
      phase: 'web-load',
      status: 'completed',
      message: 'Page failed to load',
      detail: { pageLoaded: false },
    });
    return pageLoadFailed(url, probes, errorMessage(error));
  }
  if (response === null) {
    emitProgress(onProgress, {
      phase: 'web-load',
      status: 'completed',
      message: 'Page produced no response',
      detail: { pageLoaded: false },
    });
    return pageLoadFailed(url, probes, 'Navigation produced no response (no document loaded).');
  }

  const ctx = new PlaywrightPageContext(page, response, url);
  emitProgress(onProgress, {
    phase: 'web-load',
    status: 'completed',
    message: `Page loaded (HTTP ${ctx.status})`,
    detail: { pageLoaded: true, httpStatus: ctx.status },
  });

  // --- Operation 2..n: each probe (its own timeout). ----------------------
  const results: WebProbeResult[] = [];
  const findings: Finding[] = [];

  emitProgress(onProgress, {
    phase: 'web-probes',
    status: 'started',
    message: `Running ${probes.length} DAST probe(s)`,
    detail: { probes: probes.length },
  });

  for (const probe of probes) {
    let detection: WebDetection;
    try {
      detection = await withTimeout(probeMs, `probe ${probe.id}`, probe.evaluate(ctx));
    } catch (error) {
      // Timeout OR an unexpected probe failure → NOT executed, NOT "clean".
      // The error is recorded (not swallowed) and surfaced via stats/outcome.
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'not-executed',
        rationale:
          error instanceof ProbeTimeoutError
            ? 'Probe did not execute: exceeded its per-probe timeout guard.'
            : 'Probe did not execute: it failed before producing a result.',
        error: errorMessage(error),
      });
      continue;
    }

    if (!detection.detected) {
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'clean',
        rationale: detection.rationale,
      });
      continue;
    }

    const finding = buildFinding(probe, detection, ctx);
    findings.push(finding);
    results.push({
      probeId: probe.id,
      technique: probe.technique,
      category: probe.category,
      status: 'detected',
      rationale: detection.rationale,
      finding,
    });
  }

  const stats = summarize(results);
  const outcome = deriveOutcome(stats);

  emitProgress(onProgress, {
    phase: 'web-probes',
    status: 'completed',
    message: `DAST complete: ${findings.length} finding(s), outcome ${outcome}`,
    detail: { findings: findings.length, executed: stats.executed, outcome },
  });

  return {
    url,
    finalUrl: ctx.finalUrl,
    pageLoaded: true,
    httpStatus: ctx.status,
    outcome,
    findings,
    results,
    stats,
  };
}

export interface RunWebAppScanOptions {
  /** Reuse an existing browser (caller owns its lifecycle). When omitted, one is launched and closed. */
  browser?: Browser;
  /** Chromium launch args when launching our own browser. Defaults to `DEFAULT_LAUNCH_ARGS`. */
  launchArgs?: readonly string[];
  /** Probe set to run. Defaults to `WEB_PROBES`. */
  probes?: readonly WebProbe[];
  /** Navigation completion event. Defaults to `domcontentloaded`. */
  waitUntil?: WaitUntil;
  /** Optional stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

/**
 * Run a single-page web app vulnerability scan from a validated config. Owns the
 * browser lifecycle: launches headless Chromium (unless a browser is supplied),
 * scans `config.target.url`, and always tears down the context (and the browser,
 * if it launched one).
 */
export async function runWebAppScan(
  config: WebAppVulnScanConfig,
  options: RunWebAppScanOptions = {},
): Promise<WebPageScanResult> {
  const ownBrowser = options.browser === undefined;
  const browser =
    options.browser ??
    (await chromium.launch({
      headless: true,
      args: [...(options.launchArgs ?? DEFAULT_LAUNCH_ARGS)],
    }));

  let context: BrowserContext | undefined;
  try {
    context = await browser.newContext();
    const page = await context.newPage();
    return await scanSinglePage(page, config.target.url, {
      timeouts: config.timeouts,
      ...(options.probes !== undefined ? { probes: options.probes } : {}),
      ...(options.waitUntil !== undefined ? { waitUntil: options.waitUntil } : {}),
      ...(options.onProgress !== undefined ? { onProgress: options.onProgress } : {}),
    });
  } finally {
    if (context !== undefined) {
      await closeQuietly(context);
    }
    if (ownBrowser) {
      await closeQuietly(browser);
    }
  }
}

/** Build the honest "page did not load" result: every probe is `not-executed`. */
function pageLoadFailed(
  url: string,
  probes: readonly WebProbe[],
  loadError: string,
): WebPageScanResult {
  const results: WebProbeResult[] = probes.map((probe) => ({
    probeId: probe.id,
    technique: probe.technique,
    category: probe.category,
    status: 'not-executed' as const,
    rationale: 'Probe did not execute: the page could not be loaded.',
    error: loadError,
  }));
  return {
    url,
    pageLoaded: false,
    loadError,
    outcome: 'page-load-failed',
    findings: [],
    results,
    stats: summarize(results),
  };
}

function summarize(results: readonly WebProbeResult[]): WebScanStats {
  let detected = 0;
  let clean = 0;
  let notExecuted = 0;
  for (const result of results) {
    if (result.status === 'detected') detected += 1;
    else if (result.status === 'clean') clean += 1;
    else notExecuted += 1;
  }
  return { total: results.length, executed: detected + clean, detected, clean, notExecuted };
}

function deriveOutcome(stats: WebScanStats): WebScanOutcome {
  // Reached only when the page loaded (navigation failure → `page-load-failed`).
  if (stats.detected > 0) return 'vulnerable';
  // Any probe that did not execute (timeout/error) → incomplete coverage, not a
  // clean bill. Mirrors Layer 1's `passed-with-gaps`: findings are empty but the
  // consumer MUST inspect `stats.notExecuted` before treating it as fully clean.
  if (stats.notExecuted > 0) return 'passed-with-gaps';
  return 'passed';
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Best-effort teardown. A failure to close the browser/context must NOT mask an
 * already-computed scan result, so the error is captured and intentionally not
 * rethrown — this is deliberate handling for non-fatal cleanup, not a silent swallow.
 */
async function closeQuietly(closable: { close(): Promise<void> }): Promise<void> {
  try {
    await closable.close();
  } catch {
    // Intentionally ignored: teardown is best-effort and the scan result stands.
  }
}
