import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  apiRawTargetSpecSchema,
  apiScanConfigSchema,
  DEFAULT_API_BODY_CAPTURE_MAX_CHARS,
  DEFAULT_API_REQUEST_TIMEOUT_MS,
  endpointTargetSpecSchema,
  scanConfigSchema,
} from './config';

test('scanConfigSchema accepts an AI scan with an endpoint target and token budget', () => {
  const parsed = scanConfigSchema.parse({
    type: 'ai-llm-attack',
    target: { kind: 'endpoint', url: 'https://agent.example/chat' },
    tokenBudget: 50000,
  });
  assert.equal(parsed.type, 'ai-llm-attack');
});

test('scanConfigSchema accepts an AI scan with a system-prompt target', () => {
  const parsed = scanConfigSchema.parse({
    type: 'ai-llm-attack',
    target: { kind: 'system-prompt', prompt: 'You are a banking assistant.' },
    tokenBudget: 10000,
  });
  assert.equal(parsed.type, 'ai-llm-attack');
});

test('scanConfigSchema rejects an AI scan without a token budget (required, ARCH §4.2)', () => {
  assert.equal(
    scanConfigSchema.safeParse({
      type: 'ai-llm-attack',
      target: { kind: 'system-prompt', prompt: 'x' },
    }).success,
    false,
  );
});

test('scanConfigSchema rejects a non-positive token budget', () => {
  assert.equal(
    scanConfigSchema.safeParse({
      type: 'ai-llm-attack',
      target: { kind: 'endpoint', url: 'https://agent.example' },
      tokenBudget: 0,
    }).success,
    false,
  );
});

test('scanConfigSchema accepts a web scan with a URL target', () => {
  const parsed = scanConfigSchema.parse({
    type: 'web-app-vuln',
    target: { url: 'https://app.example' },
  });
  assert.equal(parsed.type, 'web-app-vuln');
});

test('scanConfigSchema rejects an endpoint target with an invalid URL', () => {
  assert.equal(
    scanConfigSchema.safeParse({
      type: 'ai-llm-attack',
      target: { kind: 'endpoint', url: 'not-a-url' },
      tokenBudget: 100,
    }).success,
    false,
  );
});

test('scanConfigSchema rejects an unknown scan type', () => {
  assert.equal(scanConfigSchema.safeParse({ type: 'sql-scan', target: {} }).success, false);
});

test('endpointTargetSpecSchema accepts optional model and auth', () => {
  const bare = endpointTargetSpecSchema.parse({ kind: 'endpoint', url: 'https://agent.example' });
  assert.equal(bare.model, undefined);
  assert.equal(bare.auth, undefined);

  const withBearer = endpointTargetSpecSchema.parse({
    kind: 'endpoint',
    url: 'https://agent.example',
    model: 'agent-x',
    auth: { type: 'bearer', value: 'tok' },
  });
  assert.equal(withBearer.model, 'agent-x');
  assert.equal(withBearer.auth?.type, 'bearer');
});

test('endpointTargetSpecSchema: apiKey auth defaults headerName to X-API-Key', () => {
  const parsed = endpointTargetSpecSchema.parse({
    kind: 'endpoint',
    url: 'https://agent.example',
    auth: { type: 'apiKey', value: 'k-1' },
  });
  assert.equal(parsed.auth?.type, 'apiKey');
  assert.equal(parsed.auth?.type === 'apiKey' ? parsed.auth.headerName : undefined, 'X-API-Key');
});

test('endpointTargetSpecSchema rejects auth without a value', () => {
  assert.equal(
    endpointTargetSpecSchema.safeParse({
      kind: 'endpoint',
      url: 'https://agent.example',
      auth: { type: 'bearer' },
    }).success,
    false,
  );
});

// --- Phase 1.5 Sprint A1: API scan config ---

test('apiRawTargetSpecSchema: method defaults to GET when omitted', () => {
  const parsed = apiRawTargetSpecSchema.parse({
    kind: 'raw',
    url: 'https://api.example.com/v1/users/123',
  });
  assert.equal(parsed.method, 'GET');
  assert.equal(parsed.auth, undefined);
});

test('apiRawTargetSpecSchema rejects an invalid URL', () => {
  assert.equal(
    apiRawTargetSpecSchema.safeParse({ kind: 'raw', url: 'not-a-url' }).success,
    false,
  );
});

test('apiScanConfigSchema applies timeout and bodyCaptureMaxChars defaults', () => {
  const parsed = apiScanConfigSchema.parse({
    type: 'api-scan',
    target: { kind: 'raw', url: 'https://api.example.com/v1/users/123' },
  });
  assert.equal(parsed.timeoutMs, DEFAULT_API_REQUEST_TIMEOUT_MS);
  assert.equal(parsed.bodyCaptureMaxChars, DEFAULT_API_BODY_CAPTURE_MAX_CHARS);
});

test('scanConfigSchema accepts api-scan with a raw target', () => {
  const parsed = scanConfigSchema.parse({
    type: 'api-scan',
    target: { kind: 'raw', url: 'https://api.example.com/v1/users/123', method: 'POST' },
  });
  assert.equal(parsed.type, 'api-scan');
  if (parsed.type !== 'api-scan') {
    assert.fail('expected api-scan');
  }
  assert.equal(parsed.target.kind, 'raw');
  if (parsed.target.kind !== 'raw') {
    assert.fail('expected raw');
  }
  assert.equal(parsed.target.method, 'POST');
});
