import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ApiRawTargetAdapter } from './api-raw-adapter';
import { ApiSpecTargetAdapter } from './api-spec-adapter';
import type { ApiTarget } from './api-target';

/**
 * Mirrors `adapters.test.ts` for the AI side: probe logic depends only on the
 * `ApiTarget` interface, not on the mode. Adding a new adapter (e.g. GraphQL,
 * gRPC) means satisfying this interface without touching any probe.
 *
 * No network is touched here — this is the compile-time + structural proof of
 * isolation behind the interface. Each adapter's concrete behavior is covered
 * by its own *.test.ts.
 */

test('both adapters are assignable to the same ApiTarget interface (isolation behind the interface)', async () => {
  const raw = new ApiRawTargetAdapter({
    kind: 'raw',
    url: 'https://api.example.com/v1/users/123',
    method: 'GET',
  });

  const specAdapter = await ApiSpecTargetAdapter.create({
    kind: 'spec',
    document: {
      openapi: '3.0.3',
      info: { title: 't', version: '1.0' },
      servers: [{ url: 'https://api.example.com' }],
      paths: { '/ping': { get: { responses: { '200': { description: 'ok' } } } } },
    },
  });

  const targets: ApiTarget[] = [raw, specAdapter];
  assert.equal(targets.length, 2);

  // Coverage flag tells probes mode without branching on the concrete class.
  assert.equal(raw.coverage, 'raw');
  assert.equal(specAdapter.coverage, 'spec');

  // Both expose ≥ 1 endpoint and a same-shape baseUrl origin.
  assert.equal(raw.endpoints().length, 1);
  assert.equal(specAdapter.endpoints().length, 1);
  assert.equal(raw.baseUrl, 'https://api.example.com');
  assert.equal(specAdapter.baseUrl, 'https://api.example.com');
});
