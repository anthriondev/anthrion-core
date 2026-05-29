import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createScanRequestSchema } from '@anthrion/shared/scan-api';

import { createScanApiClient } from './api-client';
import { readRequestBody, startTestServer, type TestHandler } from './http-test-server';

const TOKEN = 'test-token';
const getToken = (): Promise<string | null> => Promise.resolve(TOKEN);

function json(res: import('node:http').ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

/** Run `fn` against a server with the given handler, always cleaning the server up. */
async function withServer(handler: TestHandler, fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const server = await startTestServer(handler);
  try {
    await fn(server.url);
  } finally {
    await server.close();
  }
}

test('createScan sends a valid authorized POST and returns validated data', async () => {
  let seenAuth: string | undefined;
  let seenBodyValid = false;
  await withServer(
    (req, res) => {
      void (async () => {
        seenAuth = req.headers['authorization'];
        const body: unknown = JSON.parse(await readRequestBody(req));
        seenBodyValid = createScanRequestSchema.safeParse(body).success;
        json(res, 201, {
          scanId: 'scan_1',
          status: 'QUEUED',
          scanType: 'web-app-vuln',
          createdAt: new Date().toISOString(),
        });
      })();
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.createScan({ scanType: 'web-app-vuln', target: { url: 'https://target.example' } });
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.data.scanId, 'scan_1');
        assert.equal(result.data.status, 'QUEUED');
      }
    },
  );
  assert.equal(seenAuth, `Bearer ${TOKEN}`);
  assert.equal(seenBodyValid, true);
});

test('listScans returns the validated scan list', async () => {
  await withServer(
    (_req, res) => {
      json(res, 200, {
        scans: [
          { id: 's1', status: 'DONE', scanType: 'ai-llm-attack', targetUrl: null, createdAt: new Date().toISOString(), finishedAt: new Date().toISOString() },
        ],
      });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.listScans();
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.data.scans.length, 1);
        assert.equal(result.data.scans[0]?.id, 's1');
      }
    },
  );
});

test('getScan returns the validated detail with findings', async () => {
  await withServer(
    (req, res) => {
      assert.equal(req.url, '/scans/scan_42');
      json(res, 200, {
        id: 'scan_42',
        status: 'DONE',
        scanType: 'web-app-vuln',
        targetUrl: 'https://target.example',
        targetKind: null,
        failureReason: null,
        createdAt: new Date().toISOString(),
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        payment: { kind: 'FREE_PRICING', status: 'SETTLED' },
        reportAvailable: true,
        reportCoverage: null,
        findings: [
          { id: 'f1', severity: 'HIGH', category: 'xss', title: 'Reflected XSS', description: 'desc', evidence: { input: 'in', output: 'out' }, recommendation: 'fix' },
        ],
      });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.getScan('scan_42');
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.data.findings[0]?.severity, 'HIGH');
        // T5.4 Part 1: the payment kind/status is part of the validated detail.
        assert.equal(result.data.payment?.kind, 'FREE_PRICING');
        assert.equal(result.data.payment?.status, 'SETTLED');
        // T6.1: report availability is part of the validated detail.
        assert.equal(result.data.reportAvailable, true);
      }
    },
  );
});

test('downloadReportPdf returns the PDF blob with the bearer token (T6.1)', async () => {
  let seenAuth: string | undefined;
  let seenUrl: string | undefined;
  await withServer(
    (req, res) => {
      seenAuth = req.headers['authorization'];
      seenUrl = req.url;
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      res.end(Buffer.from('%PDF-1.7\n%mock', 'latin1'));
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.downloadReportPdf('scan_42');
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.data.type, 'application/pdf');
        const text = await result.data.text();
        assert.match(text, /^%PDF-/);
      }
    },
  );
  assert.equal(seenAuth, `Bearer ${TOKEN}`);
  assert.equal(seenUrl, '/scans/scan_42/report');
});

test('downloadReportPdf surfaces a 404 as a typed http error, not a thrown surprise (T6.1)', async () => {
  await withServer(
    (_req, res) => {
      json(res, 404, { statusCode: 404, message: 'Report not available for this scan', error: 'Not Found' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.downloadReportPdf('scan_missing');
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'http');
        assert.equal(result.error.status, 404);
        assert.match(result.error.message, /not available/i);
      }
    },
  );
});

const requirements = {
  scheme: 'exact',
  network: 'base',
  maxAmountRequired: '10000',
  resource: '/scans/scan_402',
  description: 'ANTHRION security scan',
  mimeType: 'application/json',
  payTo: '0xTreasury0000000000000000000000000000beef',
  maxTimeoutSeconds: 60,
  asset: '0xUSDC00000000000000000000000000000000cafe',
};

test('createScan surfaces a 402 as a payment-required ApiError carrying PaymentRequirements (x402)', async () => {
  await withServer(
    (_req, res) => {
      json(res, 402, { x402Version: 1, accepts: [requirements], error: 'Payment required to run this scan' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.createScan({ scanType: 'web-app-vuln', target: { url: 'https://pay.example' } });
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'payment-required');
        assert.equal(result.error.status, 402);
        assert.equal(result.error.paymentRequired?.accepts[0]?.maxAmountRequired, '10000');
        assert.equal(result.error.paymentRequired?.accepts[0]?.network, 'base');
      }
    },
  );
});

// ── T-FIX.8: 429 from the throttler is mapped to a friendly `rate-limited` error ────

test('createScan maps a 429 to a `rate-limited` ApiError with friendly text (T-FIX.8)', async () => {
  await withServer(
    (_req, res) => {
      // NestJS's default ThrottlerGuard body — the class name is exactly what was
      // leaking to the UI before this fix.
      json(res, 429, { statusCode: 429, message: 'ThrottlerException: Too Many Requests' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.createScan({
        scanType: 'web-app-vuln',
        target: { url: 'https://target.example' },
      });
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'rate-limited');
        assert.equal(result.error.status, 429);
        // Friendly text — never the raw exception class name.
        assert.doesNotMatch(result.error.message, /ThrottlerException/);
        assert.match(result.error.message, /rate limit/i);
        assert.match(result.error.message, /10 scans per hour/);
        // No Retry-After header in this response → no hint surfaced.
        assert.equal(result.error.retryAfterSeconds, undefined);
      }
    },
  );
});

test('createScan parses a numeric Retry-After on 429 and exposes seconds (T-FIX.8)', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '180' });
      res.end(JSON.stringify({ statusCode: 429, message: 'ThrottlerException: Too Many Requests' }));
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.createScan({
        scanType: 'web-app-vuln',
        target: { url: 'https://target.example' },
      });
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'rate-limited');
        assert.equal(result.error.retryAfterSeconds, 180);
      }
    },
  );
});

test('createScan parses an HTTP-date Retry-After on 429 into seconds-from-now (T-FIX.8)', async () => {
  const future = new Date(Date.now() + 120_000).toUTCString();
  await withServer(
    (_req, res) => {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': future });
      res.end(JSON.stringify({ statusCode: 429 }));
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.createScan({
        scanType: 'web-app-vuln',
        target: { url: 'https://target.example' },
      });
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'rate-limited');
        assert.ok(
          result.error.retryAfterSeconds !== undefined &&
            result.error.retryAfterSeconds > 0 &&
            result.error.retryAfterSeconds <= 130,
          `expected seconds in (0, 130], got ${String(result.error.retryAfterSeconds)}`,
        );
      }
    },
  );
});

test('a 402 without a valid x402 body falls back to a generic http error', async () => {
  await withServer(
    (_req, res) => {
      json(res, 402, { statusCode: 402, message: 'nope', error: 'Payment Required' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.createScan({ scanType: 'web-app-vuln', target: { url: 'https://pay.example' } });
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'http');
        assert.equal(result.error.status, 402);
      }
    },
  );
});

test('getFreeTrialStatus returns the validated free-trial status (T5.4 Part 2)', async () => {
  await withServer(
    (req, res) => {
      assert.equal(req.url, '/payments/free-trial');
      json(res, 200, { status: 'available', walletAddress: '0xWallet0000000000000000000000000000001234' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.getFreeTrialStatus();
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.data.status, 'available');
        assert.equal(result.data.walletAddress, '0xWallet0000000000000000000000000000001234');
      }
    },
  );
});

test('a non-2xx with a NestJS error body surfaces an http ApiError with its message', async () => {
  await withServer(
    (_req, res) => {
      json(res, 404, { statusCode: 404, message: 'Scan not found', error: 'Not Found' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.getScan('missing');
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'http');
        assert.equal(result.error.status, 404);
        assert.equal(result.error.message, 'Scan not found');
      }
    },
  );
});

test('a 400 with an array message joins the validation messages', async () => {
  await withServer(
    (_req, res) => {
      json(res, 400, { statusCode: 400, message: ['target.url must be a URL', 'scanType is required'], error: 'Bad Request' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.listScans();
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.status, 400);
        assert.match(result.error.message, /target.url must be a URL; scanType is required/);
      }
    },
  );
});

test('missing token leads to a 401 surfaced as an http ApiError', async () => {
  await withServer(
    (req, res) => {
      if (req.headers['authorization'] === undefined) {
        json(res, 401, { statusCode: 401, message: 'Unauthorized', error: 'Unauthorized' });
        return;
      }
      json(res, 200, { scans: [] });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken: () => Promise.resolve(null) });
      const result = await client.listScans();
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'http');
        assert.equal(result.error.status, 401);
      }
    },
  );
});

test('a 2xx response with the wrong shape is rejected as invalid-response', async () => {
  await withServer(
    (_req, res) => {
      json(res, 200, { unexpected: 'shape' });
    },
    async (baseUrl) => {
      const client = createScanApiClient({ baseUrl, getToken });
      const result = await client.listScans();
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.kind, 'invalid-response');
      }
    },
  );
});

test('a connection failure surfaces a network ApiError (status 0)', async () => {
  // Port 1 is not listening → fetch rejects.
  const client = createScanApiClient({ baseUrl: 'http://127.0.0.1:1', getToken });
  const result = await client.listScans();
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.kind, 'network');
    assert.equal(result.error.status, 0);
  }
});

test('a throwing token provider surfaces a network ApiError', async () => {
  const client = createScanApiClient({
    baseUrl: 'http://127.0.0.1:1',
    getToken: () => Promise.reject(new Error('privy down')),
  });
  const result = await client.listScans();
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error.kind, 'network');
    assert.match(result.error.message, /access token/);
  }
});
