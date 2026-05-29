import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test, before, after } from 'node:test';

import { chromium, type Browser } from 'playwright';

import { crawlBudgetSchema, webAppVulnScanConfigSchema, type WebAppVulnScanConfig } from './config';
import { isSameOrigin, resolveAndNormalize, runWebAppCrawl } from './web-crawl';
import { RobotsTxt } from './web-robots';
import { DEFAULT_LAUNCH_ARGS } from './web-scan';

/**
 * End-to-end crawl tests (T-A2.2 + T-A2.3) using a REAL headless Chromium against a
 * REAL local HTTP server, the same pattern as `web-scan.test.ts`. Covers:
 *  - in-scope dedup (visits the seed + each unique linked page exactly once)
 *  - off-site links are ignored
 *  - `maxPages` is a HARD ceiling (Sprint A2 cost-predictability rule)
 *  - `maxDepth = 0` → only the seed
 *  - robots.txt Disallow blocks discovered URLs
 *  - aggregated findings across pages
 */

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

async function startServer(handler: Handler): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  const url = `http://127.0.0.1:${address.port}/`;
  const close = (): Promise<void> => {
    server.closeAllConnections();
    return new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  };
  return { url, close };
}

function htmlResponse(res: ServerResponse, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

function cfg(seedUrl: string, crawl?: Partial<{ maxDepth: number; maxPages: number; respectRobots: boolean }>): WebAppVulnScanConfig {
  return webAppVulnScanConfigSchema.parse({
    type: 'web-app-vuln',
    target: { url: seedUrl },
    timeouts: { navigationMs: 15000, probeMs: 5000 },
    crawl: crawl ?? {},
  });
}

// Share one browser across tests (launch is the slow part).
let browser: Browser;
before(async () => {
  browser = await chromium.launch({ headless: true, args: [...DEFAULT_LAUNCH_ARGS] });
});
after(async () => {
  await browser.close();
});

// ── Unit tests for the URL normalization helpers (no browser) ─────────────────

test('resolveAndNormalize: absolutizes relative URLs against the base', () => {
  assert.equal(resolveAndNormalize('/foo', 'http://h/bar'), 'http://h/foo');
  assert.equal(resolveAndNormalize('about', 'http://h/dir/'), 'http://h/dir/about');
});

test('resolveAndNormalize: drops the fragment so #anchor pages dedupe', () => {
  assert.equal(resolveAndNormalize('/page#sec', 'http://h/'), 'http://h/page');
});

test('resolveAndNormalize: keeps the query', () => {
  assert.equal(resolveAndNormalize('/search?q=a', 'http://h/'), 'http://h/search?q=a');
});

test('resolveAndNormalize: rejects non-http(s) schemes (mailto, javascript, data, …)', () => {
  assert.equal(resolveAndNormalize('mailto:a@b', 'http://h/'), undefined);
  assert.equal(resolveAndNormalize('javascript:alert(1)', 'http://h/'), undefined);
  assert.equal(resolveAndNormalize('data:text/html,x', 'http://h/'), undefined);
});

test('resolveAndNormalize: rejects malformed URLs', () => {
  assert.equal(resolveAndNormalize('http://[bad', 'http://h/'), undefined);
});

test('resolveAndNormalize: lowercases the host so Foo.com and foo.com dedupe', () => {
  assert.equal(resolveAndNormalize('http://Example.COM/x', 'http://h/'), 'http://example.com/x');
});

test('isSameOrigin: same host+port+scheme is same origin; differing on any one is not', () => {
  assert.equal(isSameOrigin('http://h:80/a', 'http://h:80/'), true);
  assert.equal(isSameOrigin('http://h:80/a', 'http://h:81/'), false);
  assert.equal(isSameOrigin('https://h/a', 'http://h/'), false);
  assert.equal(isSameOrigin('http://other/a', 'http://h/'), false);
});

// ── Budget schema (defaults + limits) ─────────────────────────────────────────

test('crawlBudgetSchema applies defaults', () => {
  const parsed = crawlBudgetSchema.parse({});
  assert.equal(parsed.maxDepth, 2);
  assert.equal(parsed.maxPages, 10);
  assert.equal(parsed.respectRobots, true);
});

test('crawlBudgetSchema enforces upper bounds (cost ceiling)', () => {
  assert.throws(() => crawlBudgetSchema.parse({ maxPages: 51 }));
  assert.throws(() => crawlBudgetSchema.parse({ maxDepth: 11 }));
});

test('crawlBudgetSchema rejects zero maxPages (must visit at least the seed)', () => {
  assert.throws(() => crawlBudgetSchema.parse({ maxPages: 0 }));
});

// ── End-to-end crawl behavior ─────────────────────────────────────────────────

test('crawl visits seed + linked in-scope pages, dedupes, ignores off-site', async () => {
  // Build a tiny site: / links to /a and /b and an off-site URL; /a links back to /b
  // (dedupe path). Visit count must be exactly the three in-scope pages.
  const pageHits = new Map<string, number>();
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    pageHits.set(url, (pageHits.get(url) ?? 0) + 1);
    if (url === '/' || url === '/index') {
      htmlResponse(
        res,
        `<html><body>
          <a href="/a">a</a>
          <a href="/b">b</a>
          <a href="https://off.example/x">off</a>
          <a href="#section">anchor</a>
        </body></html>`,
      );
      return;
    }
    if (url === '/a') {
      htmlResponse(res, `<html><body><a href="/b">b again</a></body></html>`);
      return;
    }
    if (url === '/b') {
      htmlResponse(res, `<html><body>leaf b</body></html>`);
      return;
    }
    if (url === '/robots.txt') {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(404).end();
  });
  try {
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 2, maxPages: 10, respectRobots: false }), {
      browser,
    });

    assert.equal(result.stopReason, 'completed', 'crawl should finish naturally');
    const visitedUrls = result.pages.map((p) => new URL(p.url).pathname);
    // Seed is always first.
    assert.equal(visitedUrls[0], '/');
    assert.equal(visitedUrls.length, 3, `expected 3 in-scope pages, got ${visitedUrls.join(', ')}`);
    assert.ok(visitedUrls.includes('/a'));
    assert.ok(visitedUrls.includes('/b'));
    // Off-site must never be visited.
    assert.equal(
      pageHits.has('https://off.example/x'),
      false,
      'off-site URL must not be hit',
    );
    // Stats are coherent.
    assert.equal(result.stats.pagesVisited, 3);
    assert.equal(result.stats.pagesLoaded, 3);
    assert.equal(result.stats.pagesFailed, 0);
  } finally {
    await server.close();
  }
});

test('crawl honors maxPages as a HARD ceiling and records unvisited discoveries', async () => {
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/robots.txt') {
      res.writeHead(404).end();
      return;
    }
    if (url === '/') {
      htmlResponse(
        res,
        `<html><body>
          <a href="/p1">1</a>
          <a href="/p2">2</a>
          <a href="/p3">3</a>
          <a href="/p4">4</a>
        </body></html>`,
      );
      return;
    }
    // Leaf pages with no further links.
    htmlResponse(res, `<html><body>leaf ${url}</body></html>`);
  });
  try {
    // Budget = 2 pages → visits seed + ONE more, the other discovered links are
    // recorded in `unvisitedDiscovered`.
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 2, maxPages: 2, respectRobots: false }), {
      browser,
    });

    assert.equal(result.stopReason, 'budget-exhausted');
    assert.equal(result.pages.length, 2, 'maxPages MUST be a hard ceiling');
    assert.ok(result.unvisitedDiscovered.length >= 1, 'unvisited links must be recorded');
    // Every unvisited entry is in-scope and not in the visited list.
    const visitedSet = new Set(result.pages.map((p) => p.url));
    for (const u of result.unvisitedDiscovered) {
      assert.equal(new URL(u).origin, result.origin);
      assert.equal(visitedSet.has(u), false);
    }
  } finally {
    await server.close();
  }
});

test('crawl with maxDepth=0 scans only the seed (no link extraction)', async () => {
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/robots.txt') {
      res.writeHead(404).end();
      return;
    }
    if (url === '/') {
      htmlResponse(res, `<html><body><a href="/never">no</a></body></html>`);
      return;
    }
    htmlResponse(res, `<html><body>should not be reached</body></html>`);
  });
  try {
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 0, maxPages: 10, respectRobots: false }), {
      browser,
    });
    assert.equal(result.pages.length, 1);
    assert.equal(result.stopReason, 'completed');
    assert.equal(result.unvisitedDiscovered.length, 0);
  } finally {
    await server.close();
  }
});

test('crawl respects robots.txt: Disallow blocks discovered URLs and records them', async () => {
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/robots.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain' }).end('User-agent: *\nDisallow: /admin\n');
      return;
    }
    if (url === '/') {
      htmlResponse(
        res,
        `<html><body>
          <a href="/public">pub</a>
          <a href="/admin">adm</a>
          <a href="/admin/secret">adm-sec</a>
        </body></html>`,
      );
      return;
    }
    if (url === '/public') {
      htmlResponse(res, `<html><body>pub leaf</body></html>`);
      return;
    }
    res.writeHead(404).end();
  });
  try {
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 2, maxPages: 10, respectRobots: true }), {
      browser,
    });
    const visitedPaths = result.pages.map((p) => new URL(p.url).pathname);
    assert.ok(visitedPaths.includes('/'));
    assert.ok(visitedPaths.includes('/public'));
    assert.equal(visitedPaths.includes('/admin'), false, '/admin must not be visited');
    assert.equal(visitedPaths.includes('/admin/secret'), false, '/admin/secret must not be visited');
    assert.ok(
      result.robotsBlocked.some((u) => new URL(u).pathname === '/admin'),
      'robots-blocked URLs must be recorded',
    );
  } finally {
    await server.close();
  }
});

test('crawl respectRobots=false bypasses robots.txt (engineer override)', async () => {
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/robots.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain' }).end('User-agent: *\nDisallow: /\n');
      return;
    }
    if (url === '/') {
      htmlResponse(res, `<html><body><a href="/x">x</a></body></html>`);
      return;
    }
    if (url === '/x') {
      htmlResponse(res, `<html><body>x</body></html>`);
      return;
    }
    res.writeHead(404).end();
  });
  try {
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 1, maxPages: 5, respectRobots: false }), {
      browser,
    });
    const visited = result.pages.map((p) => new URL(p.url).pathname);
    assert.deepEqual(visited.sort(), ['/', '/x']);
    assert.equal(result.robotsBlocked.length, 0);
  } finally {
    await server.close();
  }
});

test('crawl with custom fetchRobots: honors injected RobotsTxt', async () => {
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      htmlResponse(res, `<html><body><a href="/blocked">b</a><a href="/ok">o</a></body></html>`);
      return;
    }
    if (url === '/ok') {
      htmlResponse(res, `<html><body>ok</body></html>`);
      return;
    }
    res.writeHead(404).end();
  });
  try {
    const robots = RobotsTxt.parse('User-agent: *\nDisallow: /blocked\n');
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 1, maxPages: 5, respectRobots: true }), {
      browser,
      fetchRobots: async () => robots,
    });
    const visited = result.pages.map((p) => new URL(p.url).pathname);
    assert.ok(visited.includes('/'));
    assert.ok(visited.includes('/ok'));
    assert.equal(visited.includes('/blocked'), false);
    assert.equal(result.robotsBlocked.length, 1);
  } finally {
    await server.close();
  }
});

test('crawl aggregates findings across pages', async () => {
  // Two distinct pages, both unhardened → multiple findings each.
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/robots.txt') {
      res.writeHead(404).end();
      return;
    }
    if (url === '/') {
      htmlResponse(res, `<html><body><a href="/p">p</a></body></html>`);
      return;
    }
    if (url === '/p') {
      htmlResponse(res, `<html><body>leaf</body></html>`);
      return;
    }
    res.writeHead(404).end();
  });
  try {
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 1, maxPages: 5, respectRobots: false }), {
      browser,
    });
    assert.equal(result.pages.length, 2);
    const perPageCounts = result.pages.map((p) => p.findings.length);
    const totalCount = perPageCounts.reduce((a, b) => a + b, 0);
    assert.equal(result.findings.length, totalCount, 'aggregated findings == sum of per-page findings');
    // At least the http-only finding fires on every page.
    assert.ok(perPageCounts.every((n) => n > 0));
  } finally {
    await server.close();
  }
});

test('crawl dedupes a redirect target: a queued URL whose final URL was already visited via redirect is skipped', async () => {
  // Setup: / links to both /alias and /target. /alias 302-redirects to /target.
  // Without the finalUrl + visited-on-shift dedup, /target would be scanned twice
  // (once as the destination of /alias's redirect, then again when its own queue
  // entry is shifted). The fix records the redirect's finalUrl in `visited` and
  // re-checks `visited` at shift time, so the second visit is skipped.
  const hitCount = new Map<string, number>();
  const server = await startServer((req, res) => {
    const url = req.url ?? '/';
    hitCount.set(url, (hitCount.get(url) ?? 0) + 1);
    if (url === '/robots.txt') {
      res.writeHead(404).end();
      return;
    }
    if (url === '/') {
      htmlResponse(res, `<html><body><a href="/alias">alias</a><a href="/target">target</a></body></html>`);
      return;
    }
    if (url === '/alias') {
      res.writeHead(302, { Location: '/target' }).end();
      return;
    }
    if (url === '/target') {
      htmlResponse(res, `<html><body>target leaf</body></html>`);
      return;
    }
    res.writeHead(404).end();
  });
  try {
    const result = await runWebAppCrawl(cfg(server.url, { maxDepth: 2, maxPages: 5, respectRobots: false }), {
      browser,
    });
    // /target should appear at most once in `pages` — never double-scanned because of
    // the redirect. URLs may be either the queued URL (/alias) or the final URL
    // (/target); the invariant we care about is no duplicate /target scan.
    const targetScans = result.pages.filter((p) => p.finalUrl === `${server.url}target`).length;
    assert.equal(targetScans, 1, 'target page must be scanned exactly once (no redirect-induced duplicate)');
    // The TARGET page should be navigated to at most twice from Chromium's POV (once
    // via the /alias redirect, and at most once for any direct visit that was skipped).
    // The key cost-predictability invariant: total visits ≤ pages.length + redirects.
    assert.ok(result.pages.length <= 3, `expected ≤3 page scans, got ${result.pages.length}`);
  } finally {
    await server.close();
  }
});

test('seed page that fails to load → result.pages[0].pageLoaded is false (preserved honestly)', async () => {
  // Server that accepts then hangs → navigation timeout on the seed.
  const server = await startServer(() => {
    /* never responds */
  });
  try {
    const config = webAppVulnScanConfigSchema.parse({
      type: 'web-app-vuln',
      target: { url: server.url },
      timeouts: { navigationMs: 600, probeMs: 5000 },
      crawl: { maxDepth: 2, maxPages: 5, respectRobots: false },
    });
    const result = await runWebAppCrawl(config, { browser });
    assert.equal(result.pages.length, 1);
    const seed = result.pages[0];
    assert.ok(seed);
    assert.equal(seed.pageLoaded, false);
    assert.equal(seed.outcome, 'page-load-failed');
    assert.equal(result.stats.pagesLoaded, 0);
    assert.equal(result.stats.pagesFailed, 1);
  } finally {
    await server.close();
  }
});
