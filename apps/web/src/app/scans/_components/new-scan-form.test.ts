import assert from 'node:assert/strict';
import { test } from 'node:test';

import { createScanRequestSchema } from '@anthrion/shared/scan-api';

import {
  buildCreateScanPayload,
  hasErrors,
  initialNewScanFormState,
  validateNewScanForm,
  type NewScanFormState,
} from './new-scan-form';

function form(overrides: Partial<NewScanFormState>): NewScanFormState {
  return { ...initialNewScanFormState, ...overrides };
}

test('web scan: requires a valid http(s) URL', () => {
  assert.equal(validateNewScanForm(form({ scanKind: 'web-app-vuln', webUrl: '' })).webUrl, 'Target URL is required');
  assert.match(validateNewScanForm(form({ scanKind: 'web-app-vuln', webUrl: 'not a url' })).webUrl ?? '', /valid http/);
  assert.equal(hasErrors(validateNewScanForm(form({ scanKind: 'web-app-vuln', webUrl: 'https://t.example' }))), false);
});

test('web scan: builds a server-valid payload', () => {
  const payload = buildCreateScanPayload(form({ scanKind: 'web-app-vuln', webUrl: '  https://t.example  ' }));
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  assert.equal(payload.scanType, 'web-app-vuln');
  if (payload.scanType === 'web-app-vuln') {
    assert.equal(payload.target.url, 'https://t.example'); // trimmed
  }
});

test('web scan (single mode): payload OMITS crawl entirely — preserves the Phase 1 wire shape', () => {
  // Honesty rule (Phase 1.5 Sprint A2): adding crawl support must not change the wire
  // payload for single-page scans. Existing Phase 1 callers / payloads keep working.
  const payload = buildCreateScanPayload(
    form({ scanKind: 'web-app-vuln', webMode: 'single', webUrl: 'https://t.example' }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'web-app-vuln') {
    assert.equal('crawl' in payload, false);
  }
});

test('web scan (crawl mode): payload INCLUDES crawl with sensible defaults', () => {
  const payload = buildCreateScanPayload(
    form({ scanKind: 'web-app-vuln', webMode: 'crawl', webUrl: 'https://t.example' }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'web-app-vuln') {
    assert.ok(payload.crawl, 'crawl block must be present in crawl mode');
    // Defaults must mirror the engine schema bounds: maxPages 10, maxDepth 2, robots on.
    assert.equal(payload.crawl?.maxPages, 10);
    assert.equal(payload.crawl?.maxDepth, 2);
    assert.equal(payload.crawl?.respectRobots, true);
  }
});

test('ai endpoint: requires a valid URL and an auth value when an auth mode is chosen', () => {
  assert.equal(
    validateNewScanForm(form({ scanKind: 'ai-llm-attack', aiMode: 'endpoint', endpointUrl: '' })).endpointUrl,
    'Endpoint URL is required',
  );
  const missingAuth = validateNewScanForm(
    form({ scanKind: 'ai-llm-attack', aiMode: 'endpoint', endpointUrl: 'https://a.example', authMode: 'bearer', authValue: '' }),
  );
  assert.match(missingAuth.authValue ?? '', /Auth value is required/);
});

test('ai endpoint: builds a payload with optional model + auth (server-valid)', () => {
  const payload = buildCreateScanPayload(
    form({
      scanKind: 'ai-llm-attack',
      aiMode: 'endpoint',
      endpointUrl: 'https://a.example/chat',
      endpointModel: 'some-model',
      authMode: 'apiKey',
      authValue: 'secret',
      authHeaderName: 'X-Key',
    }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  assert.equal(payload.scanType, 'ai-llm-attack');
  if (payload.scanType === 'ai-llm-attack' && payload.target.kind === 'endpoint') {
    assert.equal(payload.target.url, 'https://a.example/chat');
    assert.equal(payload.target.model, 'some-model');
    assert.deepEqual(payload.target.auth, { type: 'apiKey', value: 'secret', headerName: 'X-Key' });
  }
});

test('ai endpoint: omits empty optional model/auth fields', () => {
  const payload = buildCreateScanPayload(
    form({ scanKind: 'ai-llm-attack', aiMode: 'endpoint', endpointUrl: 'https://a.example' }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'ai-llm-attack' && payload.target.kind === 'endpoint') {
    assert.equal('model' in payload.target, false);
    assert.equal('auth' in payload.target, false);
  }
});

test('ai system prompt: requires text and builds a valid payload', () => {
  assert.equal(
    validateNewScanForm(form({ scanKind: 'ai-llm-attack', aiMode: 'system-prompt', systemPrompt: '' })).systemPrompt,
    'System prompt is required',
  );
  const payload = buildCreateScanPayload(
    form({ scanKind: 'ai-llm-attack', aiMode: 'system-prompt', systemPrompt: 'You are a helpful assistant.' }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'ai-llm-attack' && payload.target.kind === 'system-prompt') {
    assert.equal(payload.target.prompt, 'You are a helpful assistant.');
  }
});

// ── api-scan (Phase 1.5 T-A1.4) ──────────────────────────────────────────────

test('api-scan raw: requires a valid http(s) URL', () => {
  assert.equal(
    validateNewScanForm(form({ scanKind: 'api-scan', apiMode: 'raw', apiRawUrl: '' })).apiRawUrl,
    'Endpoint URL is required',
  );
  assert.match(
    validateNewScanForm(form({ scanKind: 'api-scan', apiMode: 'raw', apiRawUrl: 'ftp://x' })).apiRawUrl ?? '',
    /valid http/,
  );
  assert.equal(
    hasErrors(validateNewScanForm(form({ scanKind: 'api-scan', apiMode: 'raw', apiRawUrl: 'https://api.example/v1/items' }))),
    false,
  );
});

test('api-scan raw: builds a server-valid payload (URL trimmed)', () => {
  const payload = buildCreateScanPayload(
    form({ scanKind: 'api-scan', apiMode: 'raw', apiRawUrl: '  https://api.example/v1/items  ' }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  assert.equal(payload.scanType, 'api-scan');
  if (payload.scanType === 'api-scan' && payload.target.kind === 'raw') {
    assert.equal(payload.target.url, 'https://api.example/v1/items');
    assert.equal('auth' in payload.target, false);
  }
});

test('api-scan raw with auth: payload includes the auth block', () => {
  const payload = buildCreateScanPayload(
    form({
      scanKind: 'api-scan',
      apiMode: 'raw',
      apiRawUrl: 'https://api.example/secure',
      authMode: 'bearer',
      authValue: 'secret-token',
    }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'api-scan' && payload.target.kind === 'raw') {
    assert.deepEqual(payload.target.auth, { type: 'bearer', value: 'secret-token' });
  }
});

test('api-scan spec: requires a JSON object document; rejects YAML / array / primitive', () => {
  // Empty
  assert.equal(
    validateNewScanForm(form({ scanKind: 'api-scan', apiMode: 'spec', apiSpecDocument: '' })).apiSpecDocument,
    'OpenAPI/Swagger spec is required (JSON)',
  );
  // YAML-like text (not JSON)
  assert.match(
    validateNewScanForm(
      form({ scanKind: 'api-scan', apiMode: 'spec', apiSpecDocument: 'openapi: 3.0.0\ninfo:\n  title: t' }),
    ).apiSpecDocument ?? '',
    /valid JSON object/,
  );
  // Array (parses but is not an object)
  assert.match(
    validateNewScanForm(form({ scanKind: 'api-scan', apiMode: 'spec', apiSpecDocument: '[]' })).apiSpecDocument ?? '',
    /valid JSON object/,
  );
  // Primitive
  assert.match(
    validateNewScanForm(form({ scanKind: 'api-scan', apiMode: 'spec', apiSpecDocument: '42' })).apiSpecDocument ?? '',
    /valid JSON object/,
  );
});

test('api-scan spec: rejects an invalid optional baseUrl', () => {
  const errors = validateNewScanForm(
    form({
      scanKind: 'api-scan',
      apiMode: 'spec',
      apiSpecDocument: '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}',
      apiSpecBaseUrl: 'not-a-url',
    }),
  );
  assert.match(errors.apiSpecBaseUrl ?? '', /valid http/);
});

// ── T-FIX.3: spec textarea — URL vs JSON detection ─────────────────────────────

test('api-scan spec (T-FIX.3): pasting a bare URL is blocked with an actionable message', () => {
  const errors = validateNewScanForm(
    form({
      scanKind: 'api-scan',
      apiMode: 'spec',
      apiSpecDocument: 'https://petstore3.swagger.io/api/v3/openapi.json',
    }),
  );
  assert.match(errors.apiSpecDocument ?? '', /looks like a URL/);
  assert.match(errors.apiSpecDocument ?? '', /copy the JSON content/);
});

test('api-scan spec (T-FIX.3): http:// URL is also detected (not only https)', () => {
  const errors = validateNewScanForm(
    form({ scanKind: 'api-scan', apiMode: 'spec', apiSpecDocument: 'http://api.example.com/openapi.json' }),
  );
  assert.match(errors.apiSpecDocument ?? '', /looks like a URL/);
});

test('api-scan spec (T-FIX.3): valid JSON still passes (URL detection does not over-fire)', () => {
  const errors = validateNewScanForm(
    form({
      scanKind: 'api-scan',
      apiMode: 'spec',
      apiSpecDocument: '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{}}}}',
    }),
  );
  assert.equal(errors.apiSpecDocument, undefined);
});

// ── T-FIX.4: BASE URL — block spec-file URLs ───────────────────────────────────

test('api-scan spec (T-FIX.4): baseUrl pointing at a .json file is blocked', () => {
  const errors = validateNewScanForm(
    form({
      scanKind: 'api-scan',
      apiMode: 'spec',
      apiSpecDocument: '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}',
      apiSpecBaseUrl: 'https://petstore3.swagger.io/api/v3/openapi.json',
    }),
  );
  assert.match(errors.apiSpecBaseUrl ?? '', /should be the API root/);
});

test('api-scan spec (T-FIX.4): baseUrl pointing at a .yaml/.yml file is blocked', () => {
  for (const suffix of ['openapi.yaml', 'spec.yml']) {
    const errors = validateNewScanForm(
      form({
        scanKind: 'api-scan',
        apiMode: 'spec',
        apiSpecDocument: '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}',
        apiSpecBaseUrl: `https://api.example.com/${suffix}`,
      }),
    );
    assert.match(errors.apiSpecBaseUrl ?? '', /should be the API root/, `failed for ${suffix}`);
  }
});

test('api-scan spec (T-FIX.4): valid API-root baseUrl still passes', () => {
  const errors = validateNewScanForm(
    form({
      scanKind: 'api-scan',
      apiMode: 'spec',
      apiSpecDocument: '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}',
      apiSpecBaseUrl: 'https://petstore3.swagger.io/api/v3',
    }),
  );
  assert.equal(errors.apiSpecBaseUrl, undefined);
});

test('api-scan spec: builds a server-valid payload with the document parsed and baseUrl forwarded', () => {
  const doc = '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{}}}}';
  const payload = buildCreateScanPayload(
    form({
      scanKind: 'api-scan',
      apiMode: 'spec',
      apiSpecDocument: doc,
      apiSpecBaseUrl: ' https://api.example ',
    }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'api-scan' && payload.target.kind === 'spec') {
    assert.equal(payload.target.baseUrl, 'https://api.example');
    // The document is the parsed JS object (NEVER a string — SSRF guard, T-A1.1).
    assert.equal(typeof payload.target.document, 'object');
    assert.equal((payload.target.document as { openapi: string }).openapi, '3.0.0');
  }
});

test('api-scan spec: omits the baseUrl key when blank', () => {
  const doc = '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}';
  const payload = buildCreateScanPayload(
    form({ scanKind: 'api-scan', apiMode: 'spec', apiSpecDocument: doc }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'api-scan' && payload.target.kind === 'spec') {
    assert.equal('baseUrl' in payload.target, false);
  }
});

// ─── Web3 dApp scan (Sprint A3, T-A3.8) ──────────────────────────────────────

test('web3 scan: requires a valid http(s) URL', () => {
  assert.equal(
    validateNewScanForm(form({ scanKind: 'web3-dapp', web3Url: '' })).web3Url,
    'dApp URL is required',
  );
  assert.match(
    validateNewScanForm(form({ scanKind: 'web3-dapp', web3Url: 'not a url' })).web3Url ?? '',
    /valid http/,
  );
  assert.equal(
    hasErrors(validateNewScanForm(form({ scanKind: 'web3-dapp', web3Url: 'https://dapp.example' }))),
    false,
  );
});

test('web3 scan: builds a server-valid payload with depth + chain', () => {
  const payload = buildCreateScanPayload(
    form({
      scanKind: 'web3-dapp',
      web3Url: '  https://dapp.example  ',
      web3Chain: 'base',
      web3WalletDepth: 'landing-page-only',
    }),
  );
  assert.equal(createScanRequestSchema.safeParse(payload).success, true);
  if (payload.scanType === 'web3-dapp') {
    assert.equal(payload.target.url, 'https://dapp.example');
    assert.equal(payload.target.chain, 'base');
    assert.equal(payload.target.walletInteractionDepth, 'landing-page-only');
  } else {
    assert.fail(`expected web3-dapp payload, got ${payload.scanType}`);
  }
});

test('web3 scan: defaults to try-connect-button depth + ethereum chain', () => {
  const payload = buildCreateScanPayload(
    form({ scanKind: 'web3-dapp', web3Url: 'https://dapp.example' }),
  );
  if (payload.scanType !== 'web3-dapp') {
    assert.fail(`expected web3-dapp payload, got ${payload.scanType}`);
  }
  assert.equal(payload.target.walletInteractionDepth, 'try-connect-button');
  assert.equal(payload.target.chain, 'ethereum');
});

test('web3 scan: payload never carries a private-key / mnemonic / wallet-connect field', () => {
  // T-A3.8 non-negotiable: no place in the form for a key, and no key field
  // should ever appear in the wire shape. The check is structural — even if a
  // future change adds a wallet field to the form state, the wire schema
  // (createScanRequestSchema) does not declare one, so Zod would strip it.
  const payload = buildCreateScanPayload(
    form({ scanKind: 'web3-dapp', web3Url: 'https://dapp.example' }),
  );
  if (payload.scanType !== 'web3-dapp') {
    assert.fail(`expected web3-dapp payload, got ${payload.scanType}`);
  }
  const targetKeys = Object.keys(payload.target);
  assert.ok(!targetKeys.includes('privateKey'));
  assert.ok(!targetKeys.includes('mnemonic'));
  assert.ok(!targetKeys.includes('walletConnect'));
  assert.ok(!targetKeys.includes('seed'));
});
