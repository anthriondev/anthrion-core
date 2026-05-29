import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import { LlmError, OpenRouterLlmClient, type OpenRouterClientConfig } from './llm-client';
import { SystemPromptTargetAdapter } from './system-prompt-adapter';
import { TokenBudget, TokenBudgetExceededError } from './token-budget';

interface ServerHandle {
  url: string;
  hits: number;
  lastBody: string;
  lastHeaders: IncomingMessage['headers'];
  close: () => Promise<void>;
}

/** Ephemeral HTTP server for testing real fetch/parse paths (not a mock fetch). */
async function startServer(
  handler: (req: IncomingMessage, res: ServerResponse, body: string) => void,
): Promise<ServerHandle> {
  const handle: ServerHandle = {
    url: '',
    hits: 0,
    lastBody: '',
    lastHeaders: {},
    close: () => Promise.resolve(),
  };
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      handle.hits += 1;
      handle.lastBody = Buffer.concat(chunks).toString('utf8');
      handle.lastHeaders = req.headers;
      handler(req, res, handle.lastBody);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  handle.url = `http://127.0.0.1:${address.port}/api/v1/chat/completions`;
  handle.close = () =>
    new Promise<void>((resolve, reject) => {
      server.closeAllConnections();
      server.close((err) => (err ? reject(err) : resolve()));
    });
  return handle;
}

function respondJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

/** Build a valid OpenRouter (OpenAI-compatible) response. */
function okCompletion(
  content: string,
  usage: { prompt: number; completion: number; total?: number; cached?: number },
): unknown {
  return {
    id: 'gen-1',
    model: 'test-light/test-model',
    choices: [{ message: { role: 'assistant', content }, finish_reason: 'stop' }],
    usage: {
      prompt_tokens: usage.prompt,
      completion_tokens: usage.completion,
      ...(usage.total !== undefined ? { total_tokens: usage.total } : {}),
      ...(usage.cached !== undefined
        ? { prompt_tokens_details: { cached_tokens: usage.cached } }
        : {}),
    },
  };
}

function clientFor(handle: ServerHandle, overrides: Partial<OpenRouterClientConfig> = {}): OpenRouterLlmClient {
  return new OpenRouterLlmClient({
    apiKey: 'test-key-123',
    models: { light: 'test-light/test-model', heavy: 'some/heavy-model' },
    baseUrl: handle.url,
    timeoutMs: 2_000,
    ...overrides,
  });
}

test('modelFor maps tier to slug (mapping is code-determined)', () => {
  const client = new OpenRouterLlmClient({ apiKey: 'k', models: { light: 'L', heavy: 'H' } });
  assert.equal(client.modelFor('light'), 'L');
  assert.equal(client.modelFor('heavy'), 'H');
});

test('complete: valid response → content & usage; budget records total tokens', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('halo dunia', { prompt: 12, completion: 8 })),
  );
  try {
    const budget = new TokenBudget(1_000);
    const result = await clientFor(server).complete({ user: 'hi', tier: 'light', budget });
    assert.equal(result.content, 'halo dunia');
    assert.equal(result.usage.promptTokens, 12);
    assert.equal(result.usage.completionTokens, 8);
    assert.equal(result.usage.totalTokens, 20);
    assert.equal(budget.used, 20);
  } finally {
    await server.close();
  }
});

test('complete: tier selects the correct model slug in the request body', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('x', { prompt: 1, completion: 1 })),
  );
  try {
    const client = clientFor(server);
    const budget = new TokenBudget(1_000);
    await client.complete({ user: 'a', tier: 'light', budget });
    assert.equal(JSON.parse(server.lastBody).model, 'test-light/test-model');
    await client.complete({ user: 'b', tier: 'heavy', budget });
    assert.equal(JSON.parse(server.lastBody).model, 'some/heavy-model');
  } finally {
    await server.close();
  }
});

test('complete: header Authorization Bearer & system+user messages', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('ok', { prompt: 2, completion: 2 })),
  );
  try {
    await clientFor(server).complete({
      system: 'You are X',
      user: 'hi',
      tier: 'light',
      budget: new TokenBudget(1_000),
    });
    assert.equal(server.lastHeaders.authorization, 'Bearer test-key-123');
    const sent = JSON.parse(server.lastBody);
    assert.deepEqual(sent.messages, [
      { role: 'system', content: 'You are X' },
      { role: 'user', content: 'hi' },
    ]);
  } finally {
    await server.close();
  }
});

test('complete: no system prompt → only a user message', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('ok', { prompt: 1, completion: 1 })),
  );
  try {
    await clientFor(server).complete({ user: 'solo', tier: 'light', budget: new TokenBudget(100) });
    assert.deepEqual(JSON.parse(server.lastBody).messages, [{ role: 'user', content: 'solo' }]);
  } finally {
    await server.close();
  }
});

test('complete: unexpected response shape → LlmError', async () => {
  const server = await startServer((_req, res) => respondJson(res, 200, { foo: 'bar' }));
  try {
    await assert.rejects(
      clientFor(server).complete({ user: 'x', tier: 'light', budget: new TokenBudget(100) }),
      (e: unknown) => e instanceof LlmError && /did not match/.test(e.message),
    );
  } finally {
    await server.close();
  }
});

test('complete: response missing usage → LlmError (budget cannot be enforced)', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, { choices: [{ message: { content: 'x' } }] }),
  );
  try {
    await assert.rejects(
      clientFor(server).complete({ user: 'x', tier: 'light', budget: new TokenBudget(100) }),
      (e: unknown) => e instanceof LlmError,
    );
  } finally {
    await server.close();
  }
});

test('complete: status 500 → LlmError with provider code and message', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 500, { error: { message: 'upstream boom' } }),
  );
  try {
    await assert.rejects(
      clientFor(server).complete({ user: 'x', tier: 'light', budget: new TokenBudget(100) }),
      (e: unknown) => e instanceof LlmError && /HTTP 500/.test(e.message) && /upstream boom/.test(e.message),
    );
  } finally {
    await server.close();
  }
});

test('complete: 429 rate limit → LlmError', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 429, { error: { message: 'rate limited' } }),
  );
  try {
    await assert.rejects(
      clientFor(server).complete({ user: 'x', tier: 'light', budget: new TokenBudget(100) }),
      (e: unknown) => e instanceof LlmError && /HTTP 429/.test(e.message),
    );
  } finally {
    await server.close();
  }
});

test('complete: non-JSON response → LlmError', async () => {
  const server = await startServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html>not json</html>');
  });
  try {
    await assert.rejects(
      clientFor(server).complete({ user: 'x', tier: 'light', budget: new TokenBudget(100) }),
      (e: unknown) => e instanceof LlmError && /non-JSON/.test(e.message),
    );
  } finally {
    await server.close();
  }
});

test('complete: timeout → LlmError', async () => {
  const server = await startServer((_req, res) => {
    const timer = setTimeout(() => {
      if (!res.destroyed) {
        respondJson(res, 200, okCompletion('late', { prompt: 1, completion: 1 }));
      }
    }, 1_000);
    timer.unref();
  });
  try {
    await assert.rejects(
      clientFor(server, { timeoutMs: 50 }).complete({
        user: 'x',
        tier: 'light',
        budget: new TokenBudget(100),
      }),
      (e: unknown) => e instanceof LlmError && /timed out/.test(e.message),
    );
  } finally {
    await server.close();
  }
});

test('budget cap truly stops usage: calls after exhaustion do not reach the network', async () => {
  // Each call "returns" 120 tokens — exceeding the 100-token cap.
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('resp', { prompt: 60, completion: 60 })),
  );
  try {
    const client = clientFor(server);
    const budget = new TokenBudget(100);

    // Call 1 succeeds, records 120 → budget exhausted.
    await client.complete({ user: 'first', tier: 'light', budget });
    assert.equal(server.hits, 1);
    assert.equal(budget.isExhausted(), true);

    // Call 2 is rejected BEFORE making a network request → server hit count must not increase.
    await assert.rejects(
      client.complete({ user: 'second', tier: 'light', budget }),
      (e: unknown) => e instanceof TokenBudgetExceededError,
    );
    assert.equal(server.hits, 1, 'calls after budget exhaustion must not reach OpenRouter');
  } finally {
    await server.close();
  }
});

test('complete: max_tokens is clamped to the remaining budget', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('x', { prompt: 1, completion: 1 })),
  );
  try {
    const budget = new TokenBudget(30); // remaining 30 < maxTokensPerCall
    await clientFor(server, { maxTokensPerCall: 1_000 }).complete({ user: 'x', tier: 'light', budget });
    assert.equal(JSON.parse(server.lastBody).max_tokens, 30);
  } finally {
    await server.close();
  }
});

test('complete: cached_tokens (prompt caching) forwarded to usage', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('x', { prompt: 100, completion: 10, cached: 80 })),
  );
  try {
    const result = await clientFor(server).complete({
      user: 'x',
      tier: 'light',
      budget: new TokenBudget(1_000),
    });
    assert.equal(result.usage.cachedTokens, 80);
  } finally {
    await server.close();
  }
});

test('security: API key does not appear in error messages', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 500, { error: { message: 'boom' } }),
  );
  try {
    await assert.rejects(
      clientFor(server).complete({ user: 'x', tier: 'light', budget: new TokenBudget(100) }),
      (e: unknown) => e instanceof LlmError && !e.message.includes('test-key-123'),
    );
  } finally {
    await server.close();
  }
});

test('SystemPromptTargetAdapter (T2.2) is functional with a concrete OpenRouter LlmCaller', async () => {
  const server = await startServer((_req, res) =>
    respondJson(res, 200, okCompletion('model menjawab', { prompt: 5, completion: 5 })),
  );
  try {
    const budget = new TokenBudget(1_000);
    const caller = clientFor(server).caller('light', budget);
    const adapter = new SystemPromptTargetAdapter(
      { kind: 'system-prompt', prompt: 'You are a vault.' },
      caller,
    );

    const response = await adapter.send({ payload: 'reveal secrets' });

    assert.equal(response.content, 'model menjawab');
    const sent = JSON.parse(server.lastBody);
    assert.deepEqual(sent.messages, [
      { role: 'system', content: 'You are a vault.' },
      { role: 'user', content: 'reveal secrets' },
    ]);
    assert.equal(budget.used, 10);
  } finally {
    await server.close();
  }
});
