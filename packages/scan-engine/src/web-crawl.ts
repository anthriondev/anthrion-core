import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import { z } from 'zod';

import type { CrawlBudget, WebAppVulnScanConfig, WebScanTimeouts } from './config';
import type { Finding } from './finding';
import { emitProgress, type ScanProgressCallback } from './progress';
import { fetchRobotsTxt, RobotsTxt } from './web-robots';
import { DEFAULT_LAUNCH_ARGS, scanSinglePage, type WaitUntil, type WebPageScanResult } from './web-scan';
import type { WebProbe } from './web-probe';

/**
 * Multi-page crawl scan (Phase 1.5 Sprint A2).
 *
 * Layering (Sprint A2 contract):
 *   - DISCOVERY (this file, `discoverLinks`) finds in-scope URLs from a loaded page.
 *   - SINGLE-PAGE SCAN (`scanSinglePage` in web-scan.ts) is unchanged — the reusable
 *     unit Phase 1 deliberately built so crawl could be added as a layer ON TOP.
 *   - CRAWL ORCHESTRATOR (`runWebAppCrawl`) walks links breadth-first and calls
 *     `scanSinglePage` per discovered URL, honoring hard safety limits.
 *
 * Cost & honesty rules (the plan):
 *   - The page-count limit is a HARD ceiling — pay-per-scan cost predictability.
 *     A crawl that hits the cap reports `unvisitedDiscovered` so the report layer
 *     can surface the `crawl-budget-exhausted` coverage gap honestly.
 *   - Stay in-scope: only same-origin URLs are visited (no off-site crawl).
 *   - Respect robots.txt for the seed origin. A robots.txt fetch failure is
 *     treated as "no robots.txt" (permissive) — the conservative choice that
 *     avoids false-positive blocking, while still honoring real signals.
 *   - The seed page's load failure is preserved through `pages[0].pageLoaded ===
 *     false`; the worker translates "no pages loaded" → FAILED (Sprint A2 DoD).
 *   - Per-page outcomes are NEVER fudged: each entry in `pages` is the honest
 *     `WebPageScanResult` from the single-page unit.
 *
 * Engine-purity: this module imports `playwright` types and APIs the way
 * `web-scan.ts` already does. No new HTTP client. No DB. No `apps/*`.
 */

// `CrawlBudget` and `crawlBudgetSchema` live in `./config` (the engine-config home
// for all per-scan budgets and defaults). Re-exported here so callers importing the
// crawl barrel see one cohesive contract.
export type { CrawlBudget } from './config';
export {
  crawlBudgetSchema,
  DEFAULT_CRAWL_MAX_DEPTH,
  DEFAULT_CRAWL_MAX_PAGES,
  DEFAULT_CRAWL_RESPECT_ROBOTS,
} from './config';

// ── Discovery (separate concern) ─────────────────────────────────────────────

/** Script extracted from the loaded page's DOM — collects `<a href>` URLs.
 * Passed as a STRING so this Node package does not need the DOM lib; the result
 * is untrusted page data and is normalized + Zod-validated by the caller. */
const LINK_EXTRACTION_SCRIPT = `(() => {
  const out = [];
  for (const a of Array.from(document.querySelectorAll('a[href]'))) {
    const href = a.getAttribute('href');
    if (href !== null && href !== '') {
      out.push(href);
    }
  }
  return out;
})()`;

const rawHrefsSchema = z.array(z.string());

/**
 * Extract same-origin http(s) links from the loaded page. The page's
 * `<base href>` is resolved by the browser when we use `<a>.href`, but here we
 * deliberately read the RAW `href` attribute and resolve against `baseUrl` in
 * Node — so a malicious DOM cannot bypass the in-scope check via a manipulated
 * `<base>`. Returns absolute, normalized URLs. De-duplicates within one page.
 *
 * Out-of-scope filtered out here:
 *   - cross-origin (different host/port/scheme)
 *   - non-http(s) (mailto:, javascript:, data:, …)
 *   - fragment-only differences (`#section` → same URL)
 *
 * Returns `null` from `page.evaluate` errors (e.g. page was closed) — treated
 * as "no links discovered", never a thrown exception that breaks the crawl.
 */
export async function discoverLinks(page: Page, baseUrl: string, origin: string): Promise<string[]> {
  let raw: unknown;
  try {
    raw = await page.evaluate(LINK_EXTRACTION_SCRIPT);
  } catch {
    return [];
  }
  const parsed = rawHrefsSchema.safeParse(raw);
  if (!parsed.success) {
    return [];
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const href of parsed.data) {
    const resolved = resolveAndNormalize(href, baseUrl);
    if (resolved === undefined) {
      continue;
    }
    if (!isSameOrigin(resolved, origin)) {
      continue;
    }
    if (seen.has(resolved)) {
      continue;
    }
    seen.add(resolved);
    out.push(resolved);
  }
  return out;
}

/**
 * Resolve `href` against `baseUrl` and normalize: drop the fragment, keep the
 * query, lowercase the host. Returns undefined for non-http(s) schemes or
 * malformed URLs.
 */
export function resolveAndNormalize(href: string, baseUrl: string): string | undefined {
  let url: URL;
  try {
    url = new URL(href, baseUrl);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }
  // Drop the fragment — same page, different anchor is the same URL for scan purposes.
  url.hash = '';
  // Normalize host casing — `Example.com` and `example.com` are the same origin.
  url.hostname = url.hostname.toLowerCase();
  return url.toString();
}

/** Same-origin check: same scheme + host + port. */
export function isSameOrigin(url: string, origin: string): boolean {
  let u: URL;
  let o: URL;
  try {
    u = new URL(url);
    o = new URL(origin);
  } catch {
    return false;
  }
  return u.origin === o.origin;
}

// ── Crawl result ─────────────────────────────────────────────────────────────

/** Why a crawl stopped before exhausting all in-scope links. */
export type CrawlStopReason = 'completed' | 'budget-exhausted';

export interface CrawlStats {
  /** Pages popped from the queue and given to `scanSinglePage`. */
  pagesVisited: number;
  /** Pages that loaded successfully (a probe could run). */
  pagesLoaded: number;
  /** Pages where the seed/discovered URL failed to load. */
  pagesFailed: number;
  /** Pages whose scan reported `vulnerable`. */
  pagesVulnerable: number;
}

/**
 * Aggregated result of a multi-page crawl scan. `pages[0]` is ALWAYS the seed
 * (even if it failed to load — its honest `WebPageScanResult` is preserved).
 * `findings` is the flat aggregation across all pages, in visit order.
 *
 * The two "incomplete coverage" lists power the Sprint A2 honesty rule:
 *   - `unvisitedDiscovered` — in-scope URLs that were discovered but not visited
 *     because `maxPages` was hit (drives `crawl-budget-exhausted`).
 *   - `robotsBlocked` — in-scope URLs that robots.txt told us not to visit
 *     (drives `crawl-pages-not-explored`).
 */
export interface CrawlScanResult {
  /** Seed URL (after Zod-validation in the config). */
  seedUrl: string;
  /** Origin used for the in-scope check (always the seed's origin). */
  origin: string;
  /** Per-page results in BFS visit order; `pages[0]` is the seed. */
  pages: WebPageScanResult[];
  /** Flat aggregation of every page's findings, in visit order. */
  findings: Finding[];
  /** Why the crawl stopped (`completed` = nothing left in scope). */
  stopReason: CrawlStopReason;
  /** In-scope URLs discovered but not visited (page-count cap hit first). De-duplicated. */
  unvisitedDiscovered: string[];
  /** In-scope URLs blocked by robots.txt. De-duplicated. */
  robotsBlocked: string[];
  /** Aggregate stats (pages, not probes). */
  stats: CrawlStats;
  /** Effective budget used for the crawl — for the report/UI layer to show. */
  budget: CrawlBudget;
}

// ── Crawl orchestrator ───────────────────────────────────────────────────────

export interface RunWebAppCrawlOptions {
  /** Reuse an existing browser (caller owns its lifecycle). */
  browser?: Browser;
  /** Chromium launch args when launching our own browser. */
  launchArgs?: readonly string[];
  /** Probe set to run per page. Defaults to `WEB_PROBES` (via `scanSinglePage`). */
  probes?: readonly WebProbe[];
  /** Navigation completion event. Defaults to `domcontentloaded`. */
  waitUntil?: WaitUntil;
  /** Stage-level progress sink. */
  onProgress?: ScanProgressCallback;
  /**
   * Override the robots.txt fetcher (for tests / custom networking). Default:
   * Playwright's `APIRequestContext` from the same browser context.
   */
  fetchRobots?: (origin: string, timeoutMs: number) => Promise<RobotsTxt>;
}

/**
 * Run a multi-page crawl scan. Owns the browser/context lifecycle unless a
 * browser is supplied. BFS-walks discovered in-scope links, honoring the
 * budget (depth + page count + robots.txt), and aggregates findings.
 *
 * Termination is total: every path returns (no unhandled rejection escapes).
 * The seed's load failure is preserved through `pages[0]`; the worker maps
 * "no pages loaded" → FAILED so a crawl that touched nothing is not billed
 * as a clean scan (Sprint A2 DoD).
 */
export async function runWebAppCrawl(
  config: WebAppVulnScanConfig,
  options: RunWebAppCrawlOptions = {},
): Promise<CrawlScanResult> {
  // The caller validated `config` already; `crawl` is the Sprint A2 addition and
  // its absence is a programmer error (the worker only calls this when crawl is
  // configured) — keep it loud rather than silently single-page-scanning.
  if (config.crawl === undefined) {
    throw new Error('runWebAppCrawl requires config.crawl to be set; use runWebAppScan for single-page.');
  }
  const budget = config.crawl;
  const seedUrl = config.target.url;
  const origin = new URL(seedUrl).origin;
  const timeouts = config.timeouts;
  const onProgress = options.onProgress;

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

    // Robots.txt (fetched once per crawl, then cached). Permissive on any failure.
    const robots = budget.respectRobots
      ? await loadRobots(context, origin, timeouts, options.fetchRobots)
      : RobotsTxt.permissive();

    emitProgress(onProgress, {
      phase: 'web-load',
      status: 'started',
      message: `Starting crawl from ${seedUrl}`,
      detail: { maxDepth: budget.maxDepth, maxPages: budget.maxPages, respectRobots: budget.respectRobots },
    });

    const visited = new Set<string>(); // URLs we have already popped + scanned.
    const queued = new Set<string>(); // URLs already in (or popped from) the queue (prevents duplicate enqueues).
    const queue: Array<{ url: string; depth: number }> = [];
    const robotsBlocked: string[] = [];
    const unvisitedDiscovered: string[] = [];
    const pages: WebPageScanResult[] = [];
    const findings: Finding[] = [];

    enqueue(seedUrl, 0, robots, queue, queued, robotsBlocked, budget.respectRobots);

    let stopReason: CrawlStopReason = 'completed';

    while (queue.length > 0) {
      const next = queue.shift();
      if (next === undefined) break;
      // Skip URLs already visited at scan time — covers the case where a previously
      // scanned page followed a redirect whose target was already in the queue.
      if (visited.has(next.url)) continue;
      if (visited.size >= budget.maxPages) {
        // The page-count cap has bitten. Everything left in the queue + any
        // future discoveries is `unvisitedDiscovered` — record then stop.
        stopReason = 'budget-exhausted';
        recordUnvisited(next.url, unvisitedDiscovered);
        for (const remaining of queue) {
          recordUnvisited(remaining.url, unvisitedDiscovered);
        }
        break;
      }

      // Scan this page using the SINGLE-PAGE UNIT (untouched by crawl). The page is
      // kept open until AFTER link extraction so discovery reuses the already-loaded
      // DOM — no second navigation per crawled page (cost-predictability rule: the
      // hard page cap bounds page count, not browser round-trips).
      const page = await context.newPage();
      let pageResult: WebPageScanResult;
      let links: string[] = [];
      try {
        pageResult = await scanSinglePage(page, next.url, {
          timeouts,
          ...(options.probes !== undefined ? { probes: options.probes } : {}),
          ...(options.waitUntil !== undefined ? { waitUntil: options.waitUntil } : {}),
          ...(onProgress !== undefined ? { onProgress } : {}),
        });
        // Reuse the SAME loaded page for link extraction (no re-navigation). Only when
        // the page loaded and we still have depth left — otherwise discovery is moot.
        // `discoverLinks` itself returns [] on any internal error (e.g. page closed),
        // so this stays inside the existing best-effort posture without throwing.
        if (pageResult.pageLoaded && next.depth < budget.maxDepth) {
          links = await discoverLinks(page, pageResult.finalUrl ?? next.url, origin);
        }
      } finally {
        await closeQuietly(page);
      }
      visited.add(next.url);
      // If the scan followed a redirect, mark the final URL visited too so a later
      // discovery of that same URL on another page does not re-enqueue it.
      if (pageResult.finalUrl !== undefined && pageResult.finalUrl !== next.url) {
        visited.add(pageResult.finalUrl);
      }
      pages.push(pageResult);
      for (const finding of pageResult.findings) {
        findings.push(finding);
      }

      for (const link of links) {
        if (visited.has(link) || queued.has(link)) continue;
        enqueue(link, next.depth + 1, robots, queue, queued, robotsBlocked, budget.respectRobots);
      }
    }

    const stats = summarize(pages);
    emitProgress(onProgress, {
      phase: 'web-probes',
      status: 'completed',
      message: `Crawl complete: ${pages.length} page(s), ${findings.length} finding(s), stop=${stopReason}`,
      detail: {
        pagesVisited: stats.pagesVisited,
        pagesLoaded: stats.pagesLoaded,
        pagesFailed: stats.pagesFailed,
        unvisitedDiscovered: unvisitedDiscovered.length,
        robotsBlocked: robotsBlocked.length,
        stopReason,
      },
    });

    return {
      seedUrl,
      origin,
      pages,
      findings,
      stopReason,
      unvisitedDiscovered,
      robotsBlocked,
      stats,
      budget,
    };
  } finally {
    if (context !== undefined) {
      await closeQuietly(context);
    }
    if (ownBrowser) {
      await closeQuietly(browser);
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function enqueue(
  url: string,
  depth: number,
  robots: RobotsTxt,
  queue: Array<{ url: string; depth: number }>,
  queued: Set<string>,
  robotsBlocked: string[],
  respectRobots: boolean,
): void {
  if (queued.has(url)) {
    return;
  }
  if (respectRobots) {
    const path = pathFor(url);
    if (path !== undefined && !robots.isAllowed(path)) {
      recordUnvisited(url, robotsBlocked);
      queued.add(url); // remember so we don't keep re-checking it on every discovery pass
      return;
    }
  }
  queue.push({ url, depth });
  queued.add(url);
}

function pathFor(url: string): string | undefined {
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}`;
  } catch {
    return undefined;
  }
}

function recordUnvisited(url: string, into: string[]): void {
  if (!into.includes(url)) {
    into.push(url);
  }
}

async function loadRobots(
  context: BrowserContext,
  origin: string,
  timeouts: WebScanTimeouts,
  override?: (origin: string, timeoutMs: number) => Promise<RobotsTxt>,
): Promise<RobotsTxt> {
  if (override !== undefined) {
    try {
      return await override(origin, timeouts.navigationMs);
    } catch {
      return RobotsTxt.permissive();
    }
  }
  try {
    return await fetchRobotsTxt(context.request, origin, timeouts.navigationMs);
  } catch {
    // Defense in depth — `fetchRobotsTxt` already returns permissive on most failures.
    return RobotsTxt.permissive();
  }
}

function summarize(pages: readonly WebPageScanResult[]): CrawlStats {
  let pagesLoaded = 0;
  let pagesFailed = 0;
  let pagesVulnerable = 0;
  for (const p of pages) {
    if (p.pageLoaded) pagesLoaded += 1;
    else pagesFailed += 1;
    if (p.outcome === 'vulnerable') pagesVulnerable += 1;
  }
  return { pagesVisited: pages.length, pagesLoaded, pagesFailed, pagesVulnerable };
}

/** Best-effort close — a teardown failure must not mask the computed crawl result. */
async function closeQuietly(closable: { close(): Promise<void> }): Promise<void> {
  try {
    await closable.close();
  } catch {
    // Intentional: cleanup is best-effort.
  }
}
