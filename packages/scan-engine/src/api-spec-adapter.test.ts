import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import { ApiSpecTargetAdapter } from './api-spec-adapter';
import { ApiTargetAdapterError, type ApiRequest } from './api-target';
import { apiSpecTargetSpecSchema, type ApiSpecTargetSpec } from './config';

function spec(input: unknown): ApiSpecTargetSpec {
  return apiSpecTargetSpecSchema.parse(input);
}

/** Minimal OpenAPI 3.0 spec — two endpoints, one server, one operationId. */
function openApi3MinimalDoc(serverUrl: string): Record<string, unknown> {
  return {
    openapi: '3.0.3',
    info: { title: 'Test API', version: '1.0.0' },
    servers: [{ url: serverUrl }],
    paths: {
      '/users/{id}': {
        get: { operationId: 'getUserById', responses: { '200': { description: 'ok' } } },
        delete: { responses: { '204': { description: 'gone' } } },
      },
      '/users': {
        post: { operationId: 'createUser', responses: { '201': { description: 'created' } } },
      },
    },
  };
}

async function withServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  run: (origin: string) => Promise<void>,
): Promise<void> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => handler(req, res));
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    await run(origin);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

test('spec adapter: coverage is "spec" and baseUrl is derived from servers[0]', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({ kind: 'spec', document: openApi3MinimalDoc('https://api.example.com/v1') }),
  );
  assert.equal(adapter.coverage, 'spec');
  assert.equal(adapter.baseUrl, 'https://api.example.com');
});

test('spec adapter: endpoints() enumerates every path × method with operationId when present', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({ kind: 'spec', document: openApi3MinimalDoc('https://api.example.com') }),
  );
  const endpoints = adapter.endpoints();
  assert.equal(endpoints.length, 3);
  // Sort by path, then method, for deterministic assertion order.
  const sorted = [...endpoints].sort((a, b) => {
    if (a.pathTemplate !== b.pathTemplate) return a.pathTemplate.localeCompare(b.pathTemplate);
    return a.method.localeCompare(b.method);
  });

  // /users POST createUser
  assert.equal(sorted[0]?.pathTemplate, '/users');
  assert.equal(sorted[0]?.method, 'POST');
  assert.equal(sorted[0]?.operationId, 'createUser');

  // /users/{id} DELETE — no operationId
  assert.equal(sorted[1]?.pathTemplate, '/users/{id}');
  assert.equal(sorted[1]?.method, 'DELETE');
  assert.equal(sorted[1]?.operationId, null);

  // /users/{id} GET getUserById
  assert.equal(sorted[2]?.pathTemplate, '/users/{id}');
  assert.equal(sorted[2]?.method, 'GET');
  assert.equal(sorted[2]?.operationId, 'getUserById');
});

test('spec adapter: explicit baseUrl overrides servers[0]', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: openApi3MinimalDoc('https://prod.example.com/v1'),
      baseUrl: 'https://staging.example.com',
    }),
  );
  assert.equal(adapter.baseUrl, 'https://staging.example.com');
});

test('spec adapter: Swagger 2.0 host + schemes derives baseUrl', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        swagger: '2.0',
        info: { title: 'old', version: '1.0' },
        host: 'legacy.example.com',
        schemes: ['https'],
        paths: { '/ping': { get: { responses: { '200': { description: 'ok' } } } } },
      },
    }),
  );
  assert.equal(adapter.baseUrl, 'https://legacy.example.com');
  assert.equal(adapter.endpoints().length, 1);
});

test('spec adapter: spec with no servers and no override → ApiTargetAdapterError', async () => {
  await assert.rejects(
    ApiSpecTargetAdapter.create(
      spec({
        kind: 'spec',
        document: {
          openapi: '3.0.3',
          info: { title: 'x', version: '1.0' },
          paths: { '/users': { get: { responses: { '200': { description: 'ok' } } } } },
        },
      }),
    ),
    (err: unknown) =>
      err instanceof ApiTargetAdapterError && /Could not determine baseUrl/.test(err.message),
  );
});

test('spec adapter: spec with zero operations → ApiTargetAdapterError', async () => {
  await assert.rejects(
    ApiSpecTargetAdapter.create(
      spec({
        kind: 'spec',
        document: {
          openapi: '3.0.3',
          info: { title: 'x', version: '1.0' },
          servers: [{ url: 'https://api.example.com' }],
          paths: {},
        },
      }),
    ),
    (err: unknown) =>
      err instanceof ApiTargetAdapterError && /no usable endpoints/.test(err.message),
  );
});

test('spec adapter: malformed spec → ApiTargetAdapterError, never crashes', async () => {
  await assert.rejects(
    ApiSpecTargetAdapter.create(
      spec({
        kind: 'spec',
        document: { not: 'a spec' },
      }),
    ),
    (err: unknown) => err instanceof ApiTargetAdapterError,
  );
});

test('spec adapter: external $ref is NOT fetched (SSRF guard via resolve.external=false)', async () => {
  // If the parser tried to resolve this $ref it would attempt to fetch the host
  // — we point at a port that has no listener, so a fetch would fail OR (worse)
  // succeed silently. With resolve.external=false the parser leaves the $ref
  // in place; dereference resolves only the internal #/components ref. The
  // adapter still parses successfully and exposes the endpoint.
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        openapi: '3.0.3',
        info: { title: 'x', version: '1.0' },
        servers: [{ url: 'https://api.example.com' }],
        paths: {
          '/ping': {
            get: {
              // External $ref — a malicious spec would point at attacker host.
              responses: { $ref: 'http://attacker.example/payload.json' },
            },
          },
        },
      },
    }),
  );
  assert.equal(adapter.endpoints().length, 1);
  assert.equal(adapter.endpoints()[0]?.pathTemplate, '/ping');
});

test('spec adapter: internal $ref IS resolved (paths can use #/components refs)', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        openapi: '3.0.3',
        info: { title: 'x', version: '1.0' },
        servers: [{ url: 'https://api.example.com' }],
        components: {
          responses: {
            Ok: { description: 'ok' },
          },
        },
        paths: {
          '/things': {
            get: {
              responses: { '200': { $ref: '#/components/responses/Ok' } },
            },
          },
        },
      },
    }),
  );
  assert.equal(adapter.endpoints().length, 1);
});

test('spec adapter: input document is not mutated (defensive clone before dereferencing)', async () => {
  const document = openApi3MinimalDoc('https://api.example.com');
  const before = JSON.stringify(document);
  await ApiSpecTargetAdapter.create(spec({ kind: 'spec', document }));
  assert.equal(JSON.stringify(document), before);
});

test('spec adapter: request() honors origin lock (same shared mechanics as raw)', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({ kind: 'spec', document: openApi3MinimalDoc('https://api.example.com') }),
  );
  const endpoint = adapter.endpoints()[0];
  if (endpoint === undefined) {
    assert.fail('expected at least one endpoint');
  }
  const req: ApiRequest = {
    endpoint,
    url: 'https://attacker.example/anything',
    method: endpoint.method,
  };
  await assert.rejects(adapter.request(req), (err: unknown) => err instanceof ApiTargetAdapterError);
});

test('spec adapter: OpenAPI 3.x servers[0].url with basePath prepends it to every pathTemplate', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        openapi: '3.0.3',
        info: { title: 'x', version: '1.0' },
        servers: [{ url: 'https://api.example.com/v1' }],
        paths: {
          '/users': { get: { responses: { '200': { description: 'ok' } } } },
          '/users/{id}': { delete: { responses: { '204': { description: 'gone' } } } },
        },
      },
    }),
  );
  assert.equal(adapter.baseUrl, 'https://api.example.com');
  const sorted = [...adapter.endpoints()].sort((a, b) =>
    a.pathTemplate.localeCompare(b.pathTemplate),
  );
  assert.equal(sorted[0]?.pathTemplate, '/v1/users');
  assert.equal(sorted[1]?.pathTemplate, '/v1/users/{id}');
});

test('spec adapter: Swagger 2.0 basePath is prepended to pathTemplate', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        swagger: '2.0',
        info: { title: 'legacy', version: '1.0' },
        host: 'legacy.example.com',
        schemes: ['https'],
        basePath: '/api/v2',
        paths: {
          '/ping': { get: { responses: { '200': { description: 'ok' } } } },
        },
      },
    }),
  );
  assert.equal(adapter.baseUrl, 'https://legacy.example.com');
  assert.equal(adapter.endpoints()[0]?.pathTemplate, '/api/v2/ping');
});

test('spec adapter: explicit baseUrl override carries its own basePath into pathTemplate', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: openApi3MinimalDoc('https://api.example.com'),
      baseUrl: 'https://staging.example.com/staging-v3',
    }),
  );
  assert.equal(adapter.baseUrl, 'https://staging.example.com');
  // /users POST is in the minimal doc → with /staging-v3 prefix.
  const create = adapter.endpoints().find((e) => e.method === 'POST');
  assert.equal(create?.pathTemplate, '/staging-v3/users');
});

test('spec adapter: trailing slash on servers[0].url is normalised away (no /users → //users)', async () => {
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        openapi: '3.0.3',
        info: { title: 'x', version: '1.0' },
        servers: [{ url: 'https://api.example.com/v1/' }],
        paths: { '/users': { get: { responses: { '200': { description: 'ok' } } } } },
      },
    }),
  );
  assert.equal(adapter.endpoints()[0]?.pathTemplate, '/v1/users');
});

test('spec adapter: relative servers[0].url without baseUrl override → friendly ApiTargetAdapterError (T-FIX.2)', async () => {
  // Petstore's spec uses `"/api/v3"`, valid per OpenAPI 3.0. Without a Base URL
  // we cannot resolve it — the error must be actionable, not the old "not a
  // valid absolute URL" line that read like a crash on a spec-compliant doc.
  await assert.rejects(
    ApiSpecTargetAdapter.create(
      spec({
        kind: 'spec',
        document: {
          openapi: '3.0.3',
          info: { title: 'petstore', version: '1.0' },
          servers: [{ url: '/api/v3' }],
          paths: { '/pet': { get: { responses: { '200': { description: 'ok' } } } } },
        },
      }),
    ),
    (err: unknown) =>
      err instanceof ApiTargetAdapterError &&
      /relative server URL/.test(err.message) &&
      /Base URL/.test(err.message) &&
      err.message.includes('/api/v3'),
  );
});

test('spec adapter: relative servers[0].url WITH baseUrl override → uses override (T-FIX.2)', async () => {
  // Same Petstore-shaped relative URL, but the user supplied a Base URL — the
  // adapter must accept the spec and treat the override as the origin (the
  // basePath baked into pathTemplate comes from the override path).
  const adapter = await ApiSpecTargetAdapter.create(
    spec({
      kind: 'spec',
      document: {
        openapi: '3.0.3',
        info: { title: 'petstore', version: '1.0' },
        servers: [{ url: '/api/v3' }],
        paths: { '/pet': { get: { responses: { '200': { description: 'ok' } } } } },
      },
      baseUrl: 'https://petstore3.swagger.io/api/v3',
    }),
  );
  assert.equal(adapter.baseUrl, 'https://petstore3.swagger.io');
  assert.equal(adapter.endpoints()[0]?.pathTemplate, '/api/v3/pet');
});

test('spec adapter: templated servers[0].url (e.g. "{scheme}://...") → ApiTargetAdapterError pointing at explicit baseUrl', async () => {
  await assert.rejects(
    ApiSpecTargetAdapter.create(
      spec({
        kind: 'spec',
        document: {
          openapi: '3.0.3',
          info: { title: 'x', version: '1.0' },
          servers: [{ url: '{scheme}://api.example.com/{version}' }],
          paths: { '/ping': { get: { responses: { '200': { description: 'ok' } } } } },
        },
      }),
    ),
    (err: unknown) =>
      err instanceof ApiTargetAdapterError && /template variables/.test(err.message) && /baseUrl/.test(err.message),
  );
});

test('spec adapter: circular document is rejected with a clean ApiTargetAdapterError, not an unhandled JSON throw', async () => {
  // A user-constructed circular object — z.record(z.string(), z.unknown())
  // admits it; JSON.stringify normally throws TypeError ("Converting circular
  // structure to JSON"). The adapter must translate that into its own error.
  const circular: Record<string, unknown> = {
    openapi: '3.0.3',
    info: { title: 'x', version: '1.0' },
    servers: [{ url: 'https://api.example.com' }],
    paths: { '/ping': { get: { responses: { '200': { description: 'ok' } } } } },
  };
  circular.self = circular;
  await assert.rejects(
    ApiSpecTargetAdapter.create(spec({ kind: 'spec', document: circular })),
    (err: unknown) =>
      err instanceof ApiTargetAdapterError && /not serialisable/.test(err.message),
  );
});

test('spec adapter: request() drives the configured server end-to-end', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    },
    async (origin) => {
      const adapter = await ApiSpecTargetAdapter.create(
        spec({ kind: 'spec', document: openApi3MinimalDoc(origin) }),
      );
      const endpoint = adapter.endpoints().find((e) => e.pathTemplate === '/users' && e.method === 'POST');
      if (endpoint === undefined) {
        assert.fail('expected POST /users');
      }
      const response = await adapter.request({
        endpoint,
        url: `${origin}/users`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"name":"alice"}',
      });
      assert.equal(response.status, 200);
      assert.equal(response.body, '{"ok":true}');
    },
  );
});
