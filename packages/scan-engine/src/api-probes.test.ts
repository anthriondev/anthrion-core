import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ApiTargetAdapterError,
  type ApiEndpoint,
  type ApiRequest,
  type ApiResponse,
  type ApiTarget,
} from './api-target';
import { API_PROBES } from './api-probes';
import { buildEndpointUrl, tryRequest } from './api-probe';

/**
 * Deterministic fake `ApiTarget` for probe tests. Lets each test script the
 * response by URL+method without touching real HTTP. Mirrors the in-memory
 * fakes used by the web probes tests.
 */
class FakeApiTarget implements ApiTarget {
  readonly baseUrl: string;
  readonly coverage: 'spec' | 'raw';
  private readonly endpointList: readonly ApiEndpoint[];
  private readonly responder: (req: ApiRequest) => ApiResponse | ApiTargetAdapterError;
  /** Captured requests in order they were made. */
  readonly captured: ApiRequest[] = [];

  constructor(opts: {
    baseUrl: string;
    coverage: 'spec' | 'raw';
    endpoints: readonly ApiEndpoint[];
    responder: (req: ApiRequest) => ApiResponse | ApiTargetAdapterError;
  }) {
    this.baseUrl = opts.baseUrl;
    this.coverage = opts.coverage;
    this.endpointList = opts.endpoints;
    this.responder = opts.responder;
  }

  endpoints(): readonly ApiEndpoint[] {
    return this.endpointList;
  }

  async request(req: ApiRequest): Promise<ApiResponse> {
    this.captured.push(req);
    const result = this.responder(req);
    if (result instanceof ApiTargetAdapterError) {
      throw result;
    }
    return result;
  }
}

const baseUrl = 'https://api.example.com';
const usersEndpoint: ApiEndpoint = { method: 'GET', pathTemplate: '/users/123', operationId: null };

function okResponse(extra: Partial<ApiResponse> = {}): ApiResponse {
  return {
    status: 200,
    headers: {},
    body: '',
    bodyTruncated: false,
    ...extra,
  };
}

function probeById(id: string) {
  const probe = API_PROBES.find((p) => p.id === id);
  if (probe === undefined) {
    throw new Error(`probe not found: ${id}`);
  }
  return probe;
}

// ── api:server-software-disclosure ──────────────────────────────────────────

test('server-software-disclosure: flags Server header', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ headers: { server: 'nginx/1.18.0' } }),
  });
  const detections = await probeById('api:server-software-disclosure').evaluate(target);
  assert.equal(detections.length, 1);
  assert.match(detections[0]?.evidence ?? '', /Server: nginx\/1\.18\.0/);
  assert.equal(detections[0]?.metadata?.server, 'nginx/1.18.0');
});

test('server-software-disclosure: flags X-Powered-By header', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ headers: { 'x-powered-by': 'Express' } }),
  });
  const detections = await probeById('api:server-software-disclosure').evaluate(target);
  assert.equal(detections.length, 1);
  assert.match(detections[0]?.evidence ?? '', /X-Powered-By: Express/);
});

test('server-software-disclosure: clean when neither header present', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse(),
  });
  const detections = await probeById('api:server-software-disclosure').evaluate(target);
  assert.equal(detections.length, 0);
});

// ── api:permissive-cors ─────────────────────────────────────────────────────

test('permissive-cors: clean when no ACAO header', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse(),
  });
  const detections = await probeById('api:permissive-cors').evaluate(target);
  assert.equal(detections.length, 0);
});

test('permissive-cors: clean for a specific origin', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () =>
      okResponse({ headers: { 'access-control-allow-origin': 'https://app.example.com' } }),
  });
  const detections = await probeById('api:permissive-cors').evaluate(target);
  assert.equal(detections.length, 0);
});

test('permissive-cors: Medium for ACAO: *', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ headers: { 'access-control-allow-origin': '*' } }),
  });
  const detections = await probeById('api:permissive-cors').evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity, 'Medium');
});

test('permissive-cors: High for ACAO: * + allow-credentials true', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () =>
      okResponse({
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true',
        },
      }),
  });
  const detections = await probeById('api:permissive-cors').evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity, 'High');
  assert.match(detections[0]?.rationale ?? '', /trust failure/);
});

test('permissive-cors (T-FIX.6): description for ACAO: * alone does NOT mention allow-credentials', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ headers: { 'access-control-allow-origin': '*' } }),
  });
  const detections = await probeById('api:permissive-cors').evaluate(target);
  assert.equal(detections.length, 1);
  const description = detections[0]?.description ?? '';
  assert.match(description, /Access-Control-Allow-Origin: \*/);
  assert.doesNotMatch(description, /Allow-Credentials/i);
  assert.match(description, /non-credentialed/);
});

test('permissive-cors (T-FIX.6): description for ACAO: * + credentials mentions both headers and the trust failure', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () =>
      okResponse({
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true',
        },
      }),
  });
  const detections = await probeById('api:permissive-cors').evaluate(target);
  assert.equal(detections.length, 1);
  const description = detections[0]?.description ?? '';
  assert.match(description, /Access-Control-Allow-Origin: \*/);
  assert.match(description, /Allow-Credentials: true/);
  assert.match(description, /trust failure/i);
});

// ── api:docs-exposed ────────────────────────────────────────────────────────

test('docs-exposed: flags GET /openapi.json with JSON spec body', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/openapi.json') {
        return okResponse({
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: '{"openapi":"3.0.3","info":{"title":"x"}}',
        });
      }
      return okResponse({ status: 404 });
    },
  });
  const detections = await probeById('api:docs-exposed').evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.docsPath, '/openapi.json');
});

test('docs-exposed: does NOT flag a SPA index.html caught by /docs', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/docs') {
        return okResponse({
          status: 200,
          headers: { 'content-type': 'text/html' },
          body: '<!doctype html><html><body><div id="root"></div></body></html>',
        });
      }
      return okResponse({ status: 404 });
    },
  });
  const detections = await probeById('api:docs-exposed').evaluate(target);
  assert.equal(detections.length, 0);
});

test('docs-exposed: flags swagger-ui HTML', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/swagger-ui.html') {
        return okResponse({
          status: 200,
          headers: { 'content-type': 'text/html' },
          body: '<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>',
        });
      }
      return okResponse({ status: 404 });
    },
  });
  const detections = await probeById('api:docs-exposed').evaluate(target);
  assert.equal(detections.length, 1);
});

test('docs-exposed: clean when every well-known path 404s', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ status: 404 }),
  });
  const detections = await probeById('api:docs-exposed').evaluate(target);
  assert.equal(detections.length, 0);
});

// ── api:no-rate-limit ───────────────────────────────────────────────────────

test('no-rate-limit: flags when 5 bursts return clean 200s with no rate-limit headers', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ status: 200 }),
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(target.captured.length, 5);
});

test('no-rate-limit: clean when ANY response is 429', async () => {
  let i = 0;
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => {
      i++;
      return i === 5 ? okResponse({ status: 429 }) : okResponse({ status: 200 });
    },
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 0);
});

test('no-rate-limit: clean when responses carry X-RateLimit-Remaining', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ headers: { 'x-ratelimit-remaining': '42' } }),
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 0);
});

test('no-rate-limit: clean when responses carry Retry-After', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ headers: { 'retry-after': '10' } }),
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 0);
});

test('no-rate-limit (T-FIX.5): clean when every burst response is 404 — endpoint does not exist', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'spec',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ status: 404 }),
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 0);
});

test('no-rate-limit (T-FIX.5): clean when every burst response is 410 — endpoint gone', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'spec',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ status: 410 }),
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 0);
});

test('no-rate-limit (T-FIX.5): still fires when responses mix 404 with a real 200 (endpoint does exist)', async () => {
  let i = 0;
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => {
      i++;
      return i === 1 ? okResponse({ status: 200 }) : okResponse({ status: 404 });
    },
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 1);
});

test('no-rate-limit (T-FIX.5): fires on 5xx without rate-limit signal (server is responding, just failing)', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse({ status: 500 }),
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 1);
});

test('no-rate-limit: connection-level throttling (adapter error) counts as a rate-limit signal', async () => {
  let i = 0;
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => {
      i++;
      return i >= 3
        ? new ApiTargetAdapterError('connection reset')
        : okResponse({ status: 200 });
    },
  });
  const detections = await probeById('api:no-rate-limit').evaluate(target);
  assert.equal(detections.length, 0);
});

// ── per-endpoint behavior with multiple endpoints (spec mode) ──────────────

// ── buildEndpointUrl unit tests ─────────────────────────────────────────────

test('buildEndpointUrl: simple concatenation baseUrl + pathTemplate', () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse(),
  });
  assert.equal(
    buildEndpointUrl(target, usersEndpoint),
    'https://api.example.com/users/123',
  );
});

test('buildEndpointUrl: substitutes path params with URL-encoding', () => {
  const endpoint: ApiEndpoint = { method: 'GET', pathTemplate: '/users/{id}', operationId: null };
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'spec',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  // Value with a slash MUST be encoded — otherwise a probe could land on a
  // different path within the same origin (origin lock would not catch it).
  assert.equal(
    buildEndpointUrl(target, endpoint, { pathParams: { id: 'a/b' } }),
    'https://api.example.com/users/a%2Fb',
  );
});

test('buildEndpointUrl: appends query params', () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => okResponse(),
  });
  assert.equal(
    buildEndpointUrl(target, usersEndpoint, { query: { q: 'alice', sort: 'asc' } }),
    'https://api.example.com/users/123?q=alice&sort=asc',
  );
});

test('buildEndpointUrl: preserves the spec basePath baked into pathTemplate', () => {
  const endpoint: ApiEndpoint = { method: 'GET', pathTemplate: '/v1/users', operationId: null };
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'spec',
    endpoints: [endpoint],
    responder: () => okResponse(),
  });
  assert.equal(buildEndpointUrl(target, endpoint), 'https://api.example.com/v1/users');
});

// ── tryRequest behavior ─────────────────────────────────────────────────────

test('tryRequest: swallows ApiTargetAdapterError into ok=false + error field', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: () => new ApiTargetAdapterError('network refused'),
  });
  const outcome = await tryRequest(target, {
    endpoint: usersEndpoint,
    url: buildEndpointUrl(target, usersEndpoint),
    method: 'GET',
  });
  assert.equal(outcome.ok, false);
  assert.ok(outcome.error instanceof ApiTargetAdapterError);
  assert.match(outcome.error?.message ?? '', /network refused/);
});

test('tryRequest: re-throws non-ApiTargetAdapterError (programmer errors propagate)', async () => {
  class BrokenTarget implements ApiTarget {
    readonly baseUrl = 'https://api.example.com';
    readonly coverage = 'raw' as const;
    endpoints(): readonly ApiEndpoint[] {
      return [usersEndpoint];
    }
    async request(): Promise<ApiResponse> {
      throw new TypeError('coding bug — not an adapter error');
    }
  }
  await assert.rejects(
    tryRequest(new BrokenTarget(), {
      endpoint: usersEndpoint,
      url: 'https://api.example.com/users/123',
      method: 'GET',
    }),
    (err: unknown) => err instanceof TypeError && /coding bug/.test(err.message),
  );
});

// ── docs-exposed YAML content-type ──────────────────────────────────────────

test('docs-exposed: flags GET /openapi.yaml with YAML spec body', async () => {
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'raw',
    endpoints: [usersEndpoint],
    responder: (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/openapi.yaml') {
        return okResponse({
          status: 200,
          headers: { 'content-type': 'application/yaml' },
          body: 'openapi: 3.0.3\ninfo:\n  title: x\n',
        });
      }
      return okResponse({ status: 404 });
    },
  });
  const detections = await probeById('api:docs-exposed').evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.docsPath, '/openapi.yaml');
});

// ── per-endpoint behavior with multiple endpoints (spec mode) ──────────────

test('per-endpoint probes iterate every endpoint a spec target exposes', async () => {
  const a: ApiEndpoint = { method: 'GET', pathTemplate: '/users', operationId: null };
  const b: ApiEndpoint = { method: 'POST', pathTemplate: '/orders', operationId: null };
  const c: ApiEndpoint = { method: 'GET', pathTemplate: '/items', operationId: null };
  const target = new FakeApiTarget({
    baseUrl,
    coverage: 'spec',
    endpoints: [a, b, c],
    responder: () => okResponse({ headers: { server: 'apache/2.4.41' } }),
  });
  const detections = await probeById('api:server-software-disclosure').evaluate(target);
  assert.equal(detections.length, 3);
  assert.deepEqual(
    detections.map((d) => d.endpoint?.pathTemplate),
    ['/users', '/orders', '/items'],
  );
});
