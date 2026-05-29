import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import { endpointTargetSpecSchema, type EndpointTargetSpec } from './config';
import { EndpointTargetAdapter } from './endpoint-adapter';
import { TargetAdapterError } from './target';

interface CapturedRequest {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  body: string;
}

/** Build an endpoint spec through the schema (applies defaults like the worker flow). */
function spec(input: unknown): EndpointTargetSpec {
  return endpointTargetSpecSchema.parse(input);
}

function respondJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
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
  const url = `http://127.0.0.1:${address.port}/v1/chat/completions`;
  try {
    await run(url, captured);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

/** URL to a closed port → simulates connection refused. */
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
  return `http://127.0.0.1:${port}/v1/chat/completions`;
}

test('endpoint adapter: payload becomes user message, response is mapped to TargetResponse', async () => {
  await withServer(
    (_req, res) =>
      respondJson(res, 200, {
        model: 'agent-x',
        choices: [{ message: { role: 'assistant', content: 'agent reply' }, finish_reason: 'stop' }],
      }),
    async (url, captured) => {
      const adapter = new EndpointTargetAdapter(spec({ kind: 'endpoint', url, model: 'agent-x' }));
      const res = await adapter.send({ payload: 'hello agent' });

      assert.equal(res.content, 'agent reply');
      assert.equal(res.metadata?.model, 'agent-x');
      assert.equal(res.metadata?.finishReason, 'stop');

      const sent = JSON.parse(captured.body);
      assert.equal(captured.method, 'POST');
      assert.equal(sent.model, 'agent-x');
      assert.deepEqual(sent.messages, [{ role: 'user', content: 'hello agent' }]);
      assert.equal(captured.headers['content-type'], 'application/json');
    },
  );
});

test('endpoint adapter: bearer auth produces the correct Authorization header', async () => {
  await withServer(
    (_req, res) => respondJson(res, 200, { choices: [{ message: { content: 'ok' } }] }),
    async (url, captured) => {
      const adapter = new EndpointTargetAdapter(
        spec({ kind: 'endpoint', url, auth: { type: 'bearer', value: 'secret-token' } }),
      );
      await adapter.send({ payload: 'p' });
      assert.equal(captured.headers.authorization, 'Bearer secret-token');
    },
  );
});

test('endpoint adapter: apiKey auth uses the default X-API-Key header', async () => {
  await withServer(
    (_req, res) => respondJson(res, 200, { choices: [{ message: { content: 'ok' } }] }),
    async (url, captured) => {
      const adapter = new EndpointTargetAdapter(
        spec({ kind: 'endpoint', url, auth: { type: 'apiKey', value: 'k-123' } }),
      );
      await adapter.send({ payload: 'p' });
      assert.equal(captured.headers['x-api-key'], 'k-123');
      assert.equal(captured.headers.authorization, undefined);
    },
  );
});

test('endpoint adapter: apiKey auth respects a custom headerName', async () => {
  await withServer(
    (_req, res) => respondJson(res, 200, { choices: [{ message: { content: 'ok' } }] }),
    async (url, captured) => {
      const adapter = new EndpointTargetAdapter(
        spec({ kind: 'endpoint', url, auth: { type: 'apiKey', value: 'k-9', headerName: 'X-Agent-Key' } }),
      );
      await adapter.send({ payload: 'p' });
      assert.equal(captured.headers['x-agent-key'], 'k-9');
    },
  );
});

test('endpoint adapter: unexpected response shape → TargetAdapterError, not a crash', async () => {
  await withServer(
    (_req, res) => respondJson(res, 200, { unexpected: 'shape' }),
    async (url) => {
      const adapter = new EndpointTargetAdapter(spec({ kind: 'endpoint', url }));
      await assert.rejects(
        adapter.send({ payload: 'p' }),
        (err: unknown) =>
          err instanceof TargetAdapterError && /did not match the expected/.test(err.message),
      );
    },
  );
});

test('endpoint adapter: non-JSON response → TargetAdapterError', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html>not json</html>');
    },
    async (url) => {
      const adapter = new EndpointTargetAdapter(spec({ kind: 'endpoint', url }));
      await assert.rejects(
        adapter.send({ payload: 'p' }),
        (err: unknown) => err instanceof TargetAdapterError && /non-JSON/.test(err.message),
      );
    },
  );
});

test('endpoint adapter: non-2xx status → TargetAdapterError with the status code', async () => {
  await withServer(
    (_req, res) => respondJson(res, 500, { error: 'boom' }),
    async (url) => {
      const adapter = new EndpointTargetAdapter(spec({ kind: 'endpoint', url }));
      await assert.rejects(
        adapter.send({ payload: 'p' }),
        (err: unknown) => err instanceof TargetAdapterError && /HTTP 500/.test(err.message),
      );
    },
  );
});

test('endpoint adapter: timeout is handled cleanly → TargetAdapterError', async () => {
  await withServer(
    (_req, res) => {
      // Reply long after the adapter times out; do not write to an already-dead socket.
      const timer = setTimeout(() => {
        if (!res.destroyed) {
          respondJson(res, 200, { choices: [{ message: { content: 'late' } }] });
        }
      }, 1000);
      timer.unref();
    },
    async (url) => {
      const adapter = new EndpointTargetAdapter(spec({ kind: 'endpoint', url }), { timeoutMs: 50 });
      await assert.rejects(
        adapter.send({ payload: 'p' }),
        (err: unknown) => err instanceof TargetAdapterError && /timed out/.test(err.message),
      );
    },
  );
});

test('endpoint adapter: connection refused → TargetAdapterError (network error)', async () => {
  const url = await closedPortUrl();
  const adapter = new EndpointTargetAdapter(spec({ kind: 'endpoint', url }), { timeoutMs: 2000 });
  await assert.rejects(
    adapter.send({ payload: 'p' }),
    (err: unknown) => err instanceof TargetAdapterError && /network error/.test(err.message),
  );
});
