import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test, before, after } from 'node:test';

import { chromium, type Browser } from 'playwright';

import { webAppVulnScanConfigSchema, type WebAppVulnScanConfig } from './config';
import { findingSchema } from './finding';
import type { PageContext, WebDetection, WebProbe } from './web-probe';
import { DEFAULT_LAUNCH_ARGS, runWebAppScan, scanSinglePage } from './web-scan';

/**
 * End-to-end web scan tests (T2.6 Part B) using a REAL headless Chromium against a
 * REAL local HTTP server (node:http) — the actual Playwright path is exercised, not
 * a full mock (the pattern T2.2 used for the endpoint adapter). Probe LOGIC is
 * unit-tested separately in `web-probes.test.ts` with an in-memory PageContext.
 */

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

/** Start an ephemeral HTTP server with a given handler; returns base URL + closer. */
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

/** A URL pointing at a port with nothing listening → connection refused. */
async function closedPortUrl(): Promise<string> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  const { port } = address;
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  return `http://127.0.0.1:${port}/`;
}

function htmlResponse(res: ServerResponse, body: string, headers: Record<string, string> = {}): void {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

function cfg(url: string, timeouts?: { navigationMs?: number; probeMs?: number }): WebAppVulnScanConfig {
  return webAppVulnScanConfigSchema.parse({
    type: 'web-app-vuln',
    target: { url },
    ...(timeouts !== undefined ? { timeouts } : {}),
  });
}

function findingIds(ids: readonly string[]): Set<string> {
  return new Set(ids);
}

// Share one browser across tests (launch is the slow part).
let browser: Browser;
before(async () => {
  browser = await chromium.launch({ headless: true, args: [...DEFAULT_LAUNCH_ARGS] });
});
after(async () => {
  await browser.close();
});

test('vulnerable page → normalised, Zod-valid Findings; outcome vulnerable', async () => {
  const server = await startServer((_req, res) => {
    // No security headers + an insecure cookie + a server error body.
    res.setHeader('Set-Cookie', 'token=abc123');
    htmlResponse(res, '<!doctype html><html><body>hello</body></html>');
  });
  try {
    const result = await runWebAppScan(cfg(server.url, { navigationMs: 15000, probeMs: 5000 }), { browser });

    assert.equal(result.pageLoaded, true);
    assert.equal(result.outcome, 'vulnerable');
    assert.ok(result.findings.length > 0, 'expected findings on an unhardened page');

    // Every emitted Finding re-validates against the Zod schema.
    for (const finding of result.findings) {
      assert.doesNotThrow(() => findingSchema.parse(finding));
    }

    const ids = findingIds(result.findings.map((f) => f.id));
    assert.ok(ids.has('web:crypto-no-https'), 'served over http → no-https must fire');
    assert.ok(ids.has('web:misconfig-missing-csp'), 'no CSP → missing-csp must fire');
    assert.ok(ids.has('web:misconfig-cookie-missing-httponly'), 'cookie without HttpOnly must fire');
  } finally {
    await server.close();
  }
});

test('hardened headers over http → only the unavoidable transport finding (no header false positives)', async () => {
  const server = await startServer((_req, res) => {
    htmlResponse(res, '<!doctype html><html><body>secure-ish</body></html>', {
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Set-Cookie': 'sid=xyz; HttpOnly; SameSite=Lax; Path=/',
    });
  });
  try {
    const result = await runWebAppScan(cfg(server.url, { navigationMs: 15000, probeMs: 5000 }), { browser });

    // Over http the only honest finding is the cleartext-transport one; the header
    // probes must NOT raise false positives on a well-configured page.
    assert.deepEqual(
      result.findings.map((f) => f.id),
      ['web:crypto-no-https'],
      `unexpected findings: ${result.findings.map((f) => f.id).join(', ')}`,
    );
    assert.equal(result.outcome, 'vulnerable'); // no-https is a real finding
  } finally {
    await server.close();
  }
});

test('unreachable URL → page-load-failed, all probes not-executed (NOT "safe")', async () => {
  const url = await closedPortUrl();
  const result = await runWebAppScan(cfg(url, { navigationMs: 4000, probeMs: 5000 }), { browser });

  assert.equal(result.pageLoaded, false);
  assert.equal(result.outcome, 'page-load-failed');
  assert.equal(result.findings.length, 0, 'an unreachable site must NOT be reported as having findings…');
  assert.notEqual(result.outcome, 'passed', '…and must NOT be reported as a clean pass');
  assert.ok(result.loadError && result.loadError.length > 0, 'a load error must be recorded');
  assert.ok(result.results.length > 0);
  for (const r of result.results) {
    assert.equal(r.status, 'not-executed');
    assert.ok(r.error && r.error.length > 0);
  }
  assert.equal(result.stats.executed, 0);
  assert.equal(result.stats.notExecuted, result.stats.total);
});

test('navigation timeout → page-load-failed (honest), not a false "safe"', async () => {
  // Server that accepts the connection but never responds → goto must time out.
  const server = await startServer(() => {
    /* intentionally never responds */
  });
  try {
    const result = await runWebAppScan(cfg(server.url, { navigationMs: 600, probeMs: 5000 }), { browser });
    assert.equal(result.pageLoaded, false);
    assert.equal(result.outcome, 'page-load-failed');
    assert.equal(result.findings.length, 0);
    assert.ok(result.loadError && /timeout|exceeded|Timeout/i.test(result.loadError), `loadError should mention timeout: ${result.loadError}`);
    for (const r of result.results) {
      assert.equal(r.status, 'not-executed');
    }
  } finally {
    await server.close();
  }
});

test('per-probe timeout → that probe is not-executed (honest), never reported clean', async () => {
  const hangingProbe: WebProbe = {
    id: 'test-hanging-probe',
    technique: 'test-hang',
    category: 'security-misconfiguration',
    severity: 'Low',
    title: 'Hanging test probe',
    description: 'A probe whose evaluation never settles, to exercise the per-probe timeout guard.',
    recommendation: 'n/a',
    evaluate: (_ctx: PageContext): Promise<WebDetection> => new Promise<WebDetection>(() => undefined),
  };

  const server = await startServer((_req, res) => htmlResponse(res, '<html><body>ok</body></html>'));
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const result = await scanSinglePage(page, server.url, {
      timeouts: { navigationMs: 15000, probeMs: 300 },
      probes: [hangingProbe],
    });
    await context.close();

    assert.equal(result.pageLoaded, true);
    assert.equal(result.results.length, 1);
    const only = result.results[0];
    assert.ok(only);
    assert.equal(only.status, 'not-executed');
    assert.notEqual(only.status, 'clean'); // a hung probe is NOT a pass
    assert.ok(only.error && /timeout guard/i.test(only.error), `expected timeout error: ${only.error}`);
    assert.equal(result.findings.length, 0);
    assert.equal(result.outcome, 'passed-with-gaps'); // incomplete coverage, not "passed"
  } finally {
    await server.close();
  }
});

test('scanSinglePage is a standalone, reusable unit (the Phase 1.5 crawl building block)', async () => {
  const serverA = await startServer((_req, res) => htmlResponse(res, '<html><body>A</body></html>'));
  const serverB = await startServer((_req, res) =>
    htmlResponse(res, '<html><body>B</body></html>', {
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    }),
  );
  try {
    // One browser + one context, MANY pages → exactly how a crawl will reuse the unit.
    const context = await browser.newContext();
    const timeouts = { navigationMs: 15000, probeMs: 5000 };

    const pageA = await context.newPage();
    const resultA = await scanSinglePage(pageA, serverA.url, { timeouts });

    const pageB = await context.newPage();
    const resultB = await scanSinglePage(pageB, serverB.url, { timeouts });

    await context.close();

    assert.equal(resultA.pageLoaded, true);
    assert.equal(resultB.pageLoaded, true);
    // A (no headers) has strictly more findings than B (hardened headers).
    assert.ok(resultA.findings.length > resultB.findings.length, 'unhardened page A should have more findings than hardened page B');
    // The unit produced independent results for each URL.
    assert.equal(resultA.url, serverA.url);
    assert.equal(resultB.url, serverB.url);
  } finally {
    await serverA.close();
    await serverB.close();
  }
});

test('runWebAppScan launches and tears down its own browser when none is supplied', async () => {
  const server = await startServer((_req, res) => htmlResponse(res, '<html><body>standalone launch</body></html>'));
  try {
    const result = await runWebAppScan(cfg(server.url, { navigationMs: 15000, probeMs: 5000 }));
    assert.equal(result.pageLoaded, true);
    assert.ok(result.findings.length > 0);
  } finally {
    await server.close();
  }
});
