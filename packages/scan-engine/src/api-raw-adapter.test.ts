import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import { ApiRawTargetAdapter } from './api-raw-adapter';
import { ApiTargetAdapterError, type ApiRequest } from './api-target';
import { apiRawTargetSpecSchema, type ApiRawTargetSpec } from './config';

interface CapturedRequest {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  body: string;
}

/** Build a raw target spec through the schema (applies defaults like the worker flow). */
function spec(input: unknown): ApiRawTargetSpec {
  return apiRawTargetSpecSchema.parse(input);
}

/** Start an ephemeral HTTP server, run `body`, then tear it down. */
async function withServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  run: (url: string, captured: CapturedRequest) => Promise<void>,
): Promise<void> {
  const captured: CapturedRequest = { method: undefined, url: undefined, headers: {}, body: '' };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      captured.method = req.method;
      captured.url = req.url;
      captured.headers = req.headers;
      captured.body = Buffer.concat(chunks).toString('utf8');
      handler(req, res);
    });
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  const url = `http://127.0.0.1:${address.port}/v1/users/123`;
  try {
    await run(url, captured);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

async function closedPortUrl(): Promise<string> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  const { port } = address;
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
  return `http://127.0.0.1:${port}/v1/users/123`;
}

function reqFor(adapter: ApiRawTargetAdapter, url: string, overrides: Partial<ApiRequest> = {}): ApiRequest {
  const [endpoint] = adapter.endpoints();
  if (endpoint === undefined) {
    throw new Error('raw adapter must expose exactly one endpoint');
  }
  return {
    endpoint,
    url,
    method: endpoint.method,
    ...overrides,
  };
}

test('raw adapter: coverage is "raw" and endpoints() returns the single configured endpoint', () => {
  const adapter = new ApiRawTargetAdapter(
    spec({ kind: 'raw', url: 'https://api.example.com/v1/users/123', method: 'POST' }),
  );
  assert.equal(adapter.coverage, 'raw');
  assert.equal(adapter.baseUrl, 'https://api.example.com');

  const endpoints = adapter.endpoints();
  assert.equal(endpoints.length, 1);
  const [endpoint] = endpoints;
  if (endpoint === undefined) {
    assert.fail('endpoint missing');
  }
  assert.equal(endpoint.method, 'POST');
  assert.equal(endpoint.pathTemplate, '/v1/users/123');
  assert.equal(endpoint.operationId, null);
});

test('raw adapter: GET request returns status, lower-cased headers, and body', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'X-Custom-Header': 'value' });
      res.end(JSON.stringify({ id: 123, name: 'alice' }));
    },
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }));
      const response = await adapter.request(reqFor(adapter, url));

      assert.equal(response.status, 200);
      assert.equal(response.headers['content-type'], 'application/json');
      assert.equal(response.headers['x-custom-header'], 'value');
      assert.equal(response.body, JSON.stringify({ id: 123, name: 'alice' }));
      assert.equal(response.bodyTruncated, false);
      assert.equal(captured.method, 'GET');
      assert.equal(captured.url, '/v1/users/123');
    },
  );
});

test('raw adapter: POST sends the body and selected method', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    },
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url, method: 'POST' }));
      const response = await adapter.request(
        reqFor(adapter, url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{"id":1}',
        }),
      );

      assert.equal(captured.method, 'POST');
      assert.equal(captured.body, '{"id":1}');
      assert.equal(captured.headers['content-type'], 'application/json');
      assert.equal(response.status, 201);
    },
  );
});

test('raw adapter: GET ignores body (HTTP semantics) — no body sent', async () => {
  await withServer(
    (_req, res) => res.end('{}'),
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }));
      await adapter.request(reqFor(adapter, url, { body: 'this-should-be-dropped' }));
      assert.equal(captured.body, '');
    },
  );
});

test('raw adapter: bearer auth produces an Authorization header', async () => {
  await withServer(
    (_req, res) => res.end('{}'),
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(
        spec({ kind: 'raw', url, auth: { type: 'bearer', value: 'secret-token' } }),
      );
      await adapter.request(reqFor(adapter, url));
      assert.equal(captured.headers.authorization, 'Bearer secret-token');
    },
  );
});

test('raw adapter: apiKey auth uses the default X-API-Key header', async () => {
  await withServer(
    (_req, res) => res.end('{}'),
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(
        spec({ kind: 'raw', url, auth: { type: 'apiKey', value: 'k-123' } }),
      );
      await adapter.request(reqFor(adapter, url));
      assert.equal(captured.headers['x-api-key'], 'k-123');
      assert.equal(captured.headers.authorization, undefined);
    },
  );
});

test('raw adapter: apiKey auth respects a custom headerName', async () => {
  await withServer(
    (_req, res) => res.end('{}'),
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(
        spec({
          kind: 'raw',
          url,
          auth: { type: 'apiKey', value: 'k-9', headerName: 'X-Agent-Key' },
        }),
      );
      await adapter.request(reqFor(adapter, url));
      assert.equal(captured.headers['x-agent-key'], 'k-9');
    },
  );
});

test('raw adapter: probe-provided header overrides adapter auth (BFLA / auth-tamper probes need this)', async () => {
  await withServer(
    (_req, res) => res.end('{}'),
    async (url, captured) => {
      const adapter = new ApiRawTargetAdapter(
        spec({ kind: 'raw', url, auth: { type: 'bearer', value: 'secret-token' } }),
      );
      await adapter.request(
        reqFor(adapter, url, { headers: { Authorization: 'Bearer tampered' } }),
      );
      assert.equal(captured.headers.authorization, 'Bearer tampered');
    },
  );
});

test('raw adapter: request to a different origin → ApiTargetAdapterError, no network call', async () => {
  const adapter = new ApiRawTargetAdapter(
    spec({ kind: 'raw', url: 'https://api.example.com/v1/users/123' }),
  );
  await assert.rejects(
    adapter.request(reqFor(adapter, 'https://attacker.example/anything')),
    (err: unknown) =>
      err instanceof ApiTargetAdapterError && /does not match target baseUrl/.test(err.message),
  );
});

test('raw adapter: oversized response body is truncated and bodyTruncated is true', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200);
      res.end('A'.repeat(10_000));
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }), { bodyCaptureMaxChars: 100 });
      const response = await adapter.request(reqFor(adapter, url));
      assert.equal(response.body.length, 100);
      assert.equal(response.bodyTruncated, true);
    },
  );
});

test('raw adapter: body within cap is returned in full with bodyTruncated false', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200);
      res.end('hello');
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }), { bodyCaptureMaxChars: 1024 });
      const response = await adapter.request(reqFor(adapter, url));
      assert.equal(response.body, 'hello');
      assert.equal(response.bodyTruncated, false);
    },
  );
});

test('raw adapter: timeout is handled cleanly → ApiTargetAdapterError', async () => {
  await withServer(
    (_req, res) => {
      const timer = setTimeout(() => {
        if (!res.destroyed) {
          res.end('late');
        }
      }, 1000);
      timer.unref();
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }), { timeoutMs: 50 });
      await assert.rejects(
        adapter.request(reqFor(adapter, url)),
        (err: unknown) =>
          err instanceof ApiTargetAdapterError && /timed out/.test(err.message),
      );
    },
  );
});

test('raw adapter: connection refused → ApiTargetAdapterError (network error)', async () => {
  const url = await closedPortUrl();
  const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }), { timeoutMs: 2000 });
  await assert.rejects(
    adapter.request(reqFor(adapter, url)),
    (err: unknown) => err instanceof ApiTargetAdapterError && /network error/.test(err.message),
  );
});

test('raw adapter: non-2xx response is returned as data (status), not thrown — probes inspect status themselves', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end('{"error":"not found"}');
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }));
      const response = await adapter.request(reqFor(adapter, url));
      assert.equal(response.status, 404);
      assert.equal(response.body, '{"error":"not found"}');
    },
  );
});

test('raw adapter: server 500 is returned as data — probes decide if it is a finding', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(500);
      res.end('boom');
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }));
      const response = await adapter.request(reqFor(adapter, url));
      assert.equal(response.status, 500);
    },
  );
});

test('raw adapter: cross-origin 3xx redirect is NOT followed (origin lock cannot be escaped via Location)', async () => {
  await withServer(
    (_req, res) => {
      // Return 301 → Location pointing at a different host. With auto-follow
      // (default), fetch would silently go off-target. The adapter sets
      // `redirect: 'manual'` so the 3xx surfaces as data and probes can decide.
      res.writeHead(301, { Location: 'https://attacker.example/anywhere' });
      res.end();
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }));
      const response = await adapter.request(reqFor(adapter, url));
      assert.equal(response.status, 301);
      assert.equal(response.headers.location, 'https://attacker.example/anywhere');
    },
  );
});

test('raw adapter: same-origin 3xx is also NOT auto-followed — probes inspect the redirect chain themselves', async () => {
  await withServer(
    (req, res) => {
      // Same-origin redirect — must still surface as 302, never silently
      // chase to /v1/users/124. Probes (e.g. open-redirect, auth chain) need
      // the raw redirect response to draw a finding.
      if (req.url === '/v1/users/123') {
        res.writeHead(302, { Location: '/v1/users/124' });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end('followed');
    },
    async (url) => {
      const adapter = new ApiRawTargetAdapter(spec({ kind: 'raw', url }));
      const response = await adapter.request(reqFor(adapter, url));
      assert.equal(response.status, 302);
      assert.equal(response.body, '');
    },
  );
});
