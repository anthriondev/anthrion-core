import './test-dom';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { createScanRequestSchema } from '@anthrion/shared/scan-api';

import { createScanApiClient } from '../../../lib/api-client';
import { readRequestBody, startTestServer, type TestServer } from '../../../lib/http-test-server';

import { NewScanScreen } from './NewScanScreen';

const getToken = (): Promise<string | null> => Promise.resolve('test-token');

interface Harness {
  server: TestServer;
  pushed: string[];
  lastBody: unknown;
  end: () => Promise<void>;
}

async function setup(
  respond: (body: unknown) => { status: number; json: unknown },
): Promise<Harness> {
  const harness: Harness = { pushed: [], lastBody: null, server: undefined as never, end: async () => undefined };
  const server = await startTestServer((req, res) => {
    void (async () => {
      const raw = await readRequestBody(req);
      harness.lastBody = raw === '' ? null : JSON.parse(raw);
      const { status, json } = respond(harness.lastBody);
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(json));
    })();
  });
  harness.server = server;
  const client = createScanApiClient({ baseUrl: server.url, getToken });
  render(<NewScanScreen client={client} push={(href) => harness.pushed.push(href)} />);
  harness.end = async () => {
    cleanup();
    await server.close();
  };
  return harness;
}

test('valid web scan submits and redirects to the new scan detail', async () => {
  const h = await setup(() => ({
    status: 201,
    json: { scanId: 'scan_new', status: 'QUEUED', scanType: 'web-app-vuln', createdAt: new Date().toISOString() },
  }));
  try {
    fireEvent.click(screen.getByText('Web app vuln'));
    fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://target.example' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.deepEqual(h.pushed, ['/scans/scan_new']));
    assert.equal(createScanRequestSchema.safeParse(h.lastBody).success, true);
    // Default scan mode is single-page → no crawl block on the wire (Phase 1 preserved).
    if (h.lastBody !== null && typeof h.lastBody === 'object') {
      assert.equal('crawl' in h.lastBody, false);
    }
  } finally {
    await h.end();
  }
});

test('web crawl mode submits a payload with the crawl block (Sprint A2)', async () => {
  const h = await setup(() => ({
    status: 201,
    json: { scanId: 'scan_crawl', status: 'QUEUED', scanType: 'web-app-vuln', createdAt: new Date().toISOString() },
  }));
  try {
    fireEvent.click(screen.getByText('Web app vuln'));
    fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://target.example' } });
    fireEvent.click(screen.getByText('Multi-page crawl'));
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.deepEqual(h.pushed, ['/scans/scan_crawl']));
    const parsed = createScanRequestSchema.safeParse(h.lastBody);
    assert.equal(parsed.success, true);
    if (parsed.success && parsed.data.scanType === 'web-app-vuln') {
      assert.ok(parsed.data.crawl, 'crawl block must be set in crawl mode');
      assert.equal(parsed.data.crawl?.maxPages, 10);
      assert.equal(parsed.data.crawl?.maxDepth, 2);
      assert.equal(parsed.data.crawl?.respectRobots, true);
    }
  } finally {
    await h.end();
  }
});

test('valid AI endpoint scan submits an ai-llm-attack payload', async () => {
  const h = await setup(() => ({
    status: 201,
    json: { scanId: 'scan_ai', status: 'QUEUED', scanType: 'ai-llm-attack', createdAt: new Date().toISOString() },
  }));
  try {
    // default scan type is AI / endpoint mode
    fireEvent.change(screen.getByLabelText('Endpoint URL'), { target: { value: 'https://agent.example/chat' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.deepEqual(h.pushed, ['/scans/scan_ai']));
    const parsed = createScanRequestSchema.safeParse(h.lastBody);
    assert.equal(parsed.success, true);
    if (parsed.success) {
      assert.equal(parsed.data.scanType, 'ai-llm-attack');
    }
  } finally {
    await h.end();
  }
});

test('client-side validation blocks submit and shows an error', async () => {
  const h = await setup(() => ({ status: 201, json: {} }));
  try {
    fireEvent.click(screen.getByText('Web app vuln'));
    // leave the URL empty
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.ok(screen.getByText('Target URL is required')));
    assert.deepEqual(h.pushed, []); // never submitted
  } finally {
    await h.end();
  }
});

test('a 402 shows the x402 requirements + honest "not active yet" scaffold, with no pay button', async () => {
  const requirements = {
    scheme: 'exact', network: 'base', maxAmountRequired: '10000', resource: '/scans/scan_402',
    description: 'ANTHRION security scan', mimeType: 'application/json',
    payTo: '0xTreasury0000000000000000000000000000beef', maxTimeoutSeconds: 60,
    asset: '0xUSDC00000000000000000000000000000000cafe',
  };
  const h = await setup(() => ({
    status: 402,
    json: { x402Version: 1, accepts: [requirements], error: 'Payment required to run this scan' },
  }));
  try {
    fireEvent.click(screen.getByText('Web app vuln'));
    fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://pay.example' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.ok(screen.getByTestId('payment-requirements-notice')));
    const notice = screen.getByTestId('payment-requirements-notice');
    assert.match(notice.textContent ?? '', /not active yet/i);
    assert.match(notice.textContent ?? '', /0.01 USDC on Base/);
    // No fake pay button anywhere in the notice, and no redirect happened.
    assert.equal(notice.querySelector('button'), null);
    assert.deepEqual(h.pushed, []);
  } finally {
    await h.end();
  }
});

test('valid api-scan raw target submits an api-scan payload (Phase 1.5 T-A1.4)', async () => {
  const h = await setup(() => ({
    status: 201,
    json: { scanId: 'scan_api_raw', status: 'QUEUED', scanType: 'api-scan', createdAt: new Date().toISOString() },
  }));
  try {
    fireEvent.click(screen.getByText('API security'));
    fireEvent.change(screen.getByLabelText('Endpoint URL'), { target: { value: 'https://api.example/v1/items/1' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.deepEqual(h.pushed, ['/scans/scan_api_raw']));
    const parsed = createScanRequestSchema.safeParse(h.lastBody);
    assert.equal(parsed.success, true);
    if (parsed.success && parsed.data.scanType === 'api-scan' && parsed.data.target.kind === 'raw') {
      assert.equal(parsed.data.target.url, 'https://api.example/v1/items/1');
    }
  } finally {
    await h.end();
  }
});

test('valid api-scan spec target submits a parsed-document payload (JSON only, T-A1.4 v1)', async () => {
  const h = await setup(() => ({
    status: 201,
    json: { scanId: 'scan_api_spec', status: 'QUEUED', scanType: 'api-scan', createdAt: new Date().toISOString() },
  }));
  try {
    fireEvent.click(screen.getByText('API security'));
    fireEvent.click(screen.getByText('OpenAPI spec'));
    const spec = '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{}}}}';
    fireEvent.change(screen.getByLabelText('OpenAPI / Swagger spec (JSON)'), { target: { value: spec } });
    fireEvent.change(screen.getByLabelText('Base URL (optional)'), { target: { value: 'https://api.example' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.deepEqual(h.pushed, ['/scans/scan_api_spec']));
    const parsed = createScanRequestSchema.safeParse(h.lastBody);
    assert.equal(parsed.success, true);
    if (parsed.success && parsed.data.scanType === 'api-scan' && parsed.data.target.kind === 'spec') {
      assert.equal(parsed.data.target.baseUrl, 'https://api.example');
      assert.equal(typeof parsed.data.target.document, 'object');
    }
  } finally {
    await h.end();
  }
});

test('api-scan spec mode rejects YAML/non-object documents client-side (no submit)', async () => {
  const h = await setup(() => ({ status: 201, json: {} }));
  try {
    fireEvent.click(screen.getByText('API security'));
    fireEvent.click(screen.getByText('OpenAPI spec'));
    fireEvent.change(screen.getByLabelText('OpenAPI / Swagger spec (JSON)'), {
      target: { value: 'openapi: 3.0.0\ninfo:\n  title: t' },
    });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.ok(screen.getByText(/valid JSON object/)));
    assert.deepEqual(h.pushed, []);
  } finally {
    await h.end();
  }
});

// ── T-FIX.8: friendly 429 UX ──────────────────────────────────────────────────

test('a 429 from the api shows a friendly on-brand notice, not the raw ThrottlerException text', async () => {
  const h = await setup(() => ({
    status: 429,
    json: { statusCode: 429, message: 'ThrottlerException: Too Many Requests' },
  }));
  try {
    fireEvent.click(screen.getByText('Web app vuln'));
    fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://target.example' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.ok(screen.getByTestId('rate-limit-notice')));
    const notice = screen.getByTestId('rate-limit-notice');
    // Friendly, on-brand text — the exception class name must NOT appear.
    assert.doesNotMatch(notice.textContent ?? '', /ThrottlerException/);
    assert.match(notice.textContent ?? '', /Scan rate limit reached/);
    assert.match(notice.textContent ?? '', /10 scans per hour/);
    // The generic submit-error path is suppressed so the raw message never shows.
    assert.equal(screen.queryByTestId('submit-error'), null);
    assert.deepEqual(h.pushed, []);
  } finally {
    await h.end();
  }
});

test('a 429 with a Retry-After header surfaces a "try again in N" hint', async () => {
  const server = await startTestServer((_req, res) => {
    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '180' });
    res.end(JSON.stringify({ statusCode: 429 }));
  });
  try {
    const { createScanApiClient } = await import('../../../lib/api-client');
    const client = createScanApiClient({ baseUrl: server.url, getToken });
    const pushed: string[] = [];
    render(<NewScanScreen client={client} push={(href) => pushed.push(href)} />);

    fireEvent.click(screen.getByText('Web app vuln'));
    fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://target.example' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.ok(screen.getByTestId('rate-limit-notice')));
    const notice = screen.getByTestId('rate-limit-notice');
    assert.match(notice.textContent ?? '', /Try again in 3 minutes/);
    assert.deepEqual(pushed, []);
  } finally {
    cleanup();
    await server.close();
  }
});

test('a server error on submit is surfaced and does not redirect', async () => {
  const h = await setup(() => ({
    status: 400,
    json: { statusCode: 400, message: 'Invalid scan request', error: 'Bad Request' },
  }));
  try {
    fireEvent.click(screen.getByText('Web app vuln'));
    fireEvent.change(screen.getByLabelText('Target URL'), { target: { value: 'https://target.example' } });
    fireEvent.click(screen.getByText('Start scan'));

    await waitFor(() => assert.ok(screen.getByTestId('submit-error')));
    assert.match(screen.getByTestId('submit-error').textContent ?? '', /Invalid scan request/);
    assert.deepEqual(h.pushed, []);
  } finally {
    await h.end();
  }
});
