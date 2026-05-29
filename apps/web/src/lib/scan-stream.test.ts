import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ScanStreamEvent } from '@anthrion/shared/scan-stream';

import { EventStreamParser, consumeScanStream, type ScanStreamError } from './scan-stream';
import { sseEvent, startTestServer, type TestHandler } from './http-test-server';

// ── Pure parser: deterministic chunking ──────────────────────────────────────

function collect(): { parser: EventStreamParser; data: string[] } {
  const data: string[] = [];
  const parser = new EventStreamParser((d) => data.push(d));
  return { parser, data };
}

test('parser emits one event per complete data block', () => {
  const { parser, data } = collect();
  parser.feed('data: {"a":1}\n\n');
  assert.deepEqual(data, ['{"a":1}']);
});

test('parser emits multiple events delivered in a single chunk', () => {
  const { parser, data } = collect();
  parser.feed('data: {"a":1}\n\ndata: {"b":2}\n\n');
  assert.deepEqual(data, ['{"a":1}', '{"b":2}']);
});

test('parser buffers an event split mid-stream across chunks', () => {
  const { parser, data } = collect();
  parser.feed('data: {"hel');
  assert.deepEqual(data, []); // nothing yet — event incomplete
  parser.feed('lo":true}\n');
  assert.deepEqual(data, []); // still no terminating blank line
  parser.feed('\n');
  assert.deepEqual(data, ['{"hello":true}']);
});

test('parser tolerates CRLF line endings', () => {
  const { parser, data } = collect();
  parser.feed('data: {"a":1}\r\n\r\n');
  assert.deepEqual(data, ['{"a":1}']);
});

test('parser ignores comments and joins multiple data lines', () => {
  const { parser, data } = collect();
  parser.feed(': keep-alive\n');
  parser.feed('data: line1\ndata: line2\n\n');
  assert.deepEqual(data, ['line1\nline2']);
});

test('parser ignores a blank line with no preceding data', () => {
  const { parser, data } = collect();
  parser.feed('\n');
  parser.feed(': comment only\n\n');
  assert.deepEqual(data, []);
});

// ── Integration: real fetch + ReadableStream against a local SSE server ───────

async function withServer(handler: TestHandler, fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const server = await startTestServer(handler);
  try {
    await fn(server.url);
  } finally {
    await server.close();
  }
}

const getToken = (): Promise<string | null> => Promise.resolve('test-token');

test('consumeScanStream delivers validated events and closes on server end', async () => {
  await withServer(
    (req, res) => {
      assert.equal(req.headers['authorization'], 'Bearer test-token');
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(sseEvent({ type: 'lifecycle', status: 'RUNNING' }));
      res.write(sseEvent({ type: 'stage', phase: 'layer-1', status: 'started', message: 'probing' }));
      res.write(sseEvent({ type: 'lifecycle', status: 'DONE', message: 'done' }));
      res.end();
    },
    async (baseUrl) => {
      const events: ScanStreamEvent[] = [];
      let closed = false;
      await consumeScanStream({
        baseUrl,
        scanId: 'scan_1',
        getToken,
        onEvent: (e) => events.push(e),
        onClose: () => {
          closed = true;
        },
      });
      assert.equal(closed, true);
      assert.equal(events.length, 3);
      const last = events[2];
      assert.equal(last?.type, 'lifecycle');
      if (last?.type === 'lifecycle') {
        assert.equal(last.status, 'DONE');
      }
    },
  );
});

test('consumeScanStream reports invalid events and keeps consuming', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(sseEvent({ type: 'lifecycle', status: 'RUNNING' }));
      res.write('data: not-json\n\n'); // invalid JSON
      res.write(sseEvent({ type: 'bogus' })); // valid JSON, wrong shape
      res.write(sseEvent({ type: 'lifecycle', status: 'DONE' }));
      res.end();
    },
    async (baseUrl) => {
      const events: ScanStreamEvent[] = [];
      const errors: ScanStreamError[] = [];
      await consumeScanStream({
        baseUrl,
        scanId: 'scan_1',
        getToken,
        onEvent: (e) => events.push(e),
        onError: (e) => errors.push(e),
      });
      assert.equal(events.length, 2); // the two valid lifecycle events
      assert.equal(errors.length, 2); // the bad-JSON + wrong-shape events
      assert.ok(errors.every((e) => e.kind === 'invalid-event'));
    },
  );
});

test('consumeScanStream can be aborted mid-stream and cleans up', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(sseEvent({ type: 'lifecycle', status: 'RUNNING' }));
      // Connection deliberately kept open — the client aborts.
    },
    async (baseUrl) => {
      const controller = new AbortController();
      const events: ScanStreamEvent[] = [];
      let closed = false;
      await consumeScanStream({
        baseUrl,
        scanId: 'scan_1',
        getToken,
        signal: controller.signal,
        onEvent: (e) => {
          events.push(e);
          controller.abort(); // cancel after the first event (e.g. React unmount)
        },
        onClose: () => {
          closed = true;
        },
      });
      assert.equal(events.length, 1);
      assert.equal(closed, true);
    },
  );
});

test('consumeScanStream surfaces a non-2xx stream status as an http error', async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ statusCode: 401, message: 'Unauthorized' }));
    },
    async (baseUrl) => {
      const errors: ScanStreamError[] = [];
      let closed = false;
      await consumeScanStream({
        baseUrl,
        scanId: 'scan_1',
        getToken,
        onEvent: () => undefined,
        onError: (e) => errors.push(e),
        onClose: () => {
          closed = true;
        },
      });
      assert.equal(errors.length, 1);
      assert.equal(errors[0]?.kind, 'http');
      assert.equal(errors[0]?.status, 401);
      assert.equal(closed, false); // never opened → no close
    },
  );
});
