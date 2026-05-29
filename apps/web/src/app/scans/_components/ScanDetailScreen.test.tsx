import './test-dom';

import assert from 'node:assert/strict';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { test } from 'node:test';

import { cleanup, render, screen, waitFor } from '@testing-library/react';

import type { ScanStatusWire } from '@anthrion/shared/scan-api';

import { createScanApiClient } from '../../../lib/api-client';
import { sseEvent, startTestServer, type TestHandler, type TestServer } from '../../../lib/http-test-server';

import { ScanDetailScreen } from './ScanDetailScreen';

const SCAN_ID = 'scan_1';
const getToken = (): Promise<string | null> => Promise.resolve('test-token');

function detailJson(status: ScanStatusWire, overrides: Record<string, unknown> = {}): unknown {
  return {
    id: SCAN_ID,
    status,
    scanType: 'ai-llm-attack',
    targetUrl: 'https://agent.example',
    targetKind: 'endpoint',
    failureReason: null,
    createdAt: '2026-05-25T10:00:00.000Z',
    startedAt: status === 'QUEUED' ? null : '2026-05-25T10:00:01.000Z',
    finishedAt: status === 'DONE' || status === 'FAILED' ? '2026-05-25T10:05:00.000Z' : null,
    payment: { kind: 'FREE_PRICING', status: 'SETTLED' },
    reportAvailable: false,
    reportCoverage: null,
    findings: [],
    ...overrides,
  };
}

function renderDetail(server: TestServer): void {
  const client = createScanApiClient({ baseUrl: server.url, getToken });
  render(<ScanDetailScreen scanId={SCAN_ID} client={client} getToken={getToken} baseUrl={server.url} />);
}

async function withServer(handler: TestHandler, fn: (server: TestServer) => Promise<void>): Promise<void> {
  const server = await startTestServer(handler);
  try {
    await fn(server);
  } finally {
    cleanup();
    await server.close();
  }
}

test('streams live events, then re-fetches findings into the report on completion', async () => {
  // The snapshot loads RUNNING (no findings yet); after the live DONE event the screen
  // re-fetches, and the persisted finding is now returned and rendered.
  let detailCalls = 0;
  const finding = {
    id: 'f1',
    severity: 'HIGH',
    category: 'prompt-injection',
    title: 'System prompt leaked',
    description: 'The target revealed its system prompt.',
    evidence: { input: 'ignore previous instructions', output: 'my hidden rules are…' },
    recommendation: 'Add instruction separation.',
  };
  const handler: TestHandler = (req, res) => {
    if (req.url === `/scans/${SCAN_ID}`) {
      detailCalls += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(detailCalls === 1 ? detailJson('RUNNING') : detailJson('DONE', { findings: [finding] })));
      return;
    }
    if (req.url === `/scans/${SCAN_ID}/stream`) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(sseEvent({ type: 'stage', phase: 'layer-1', status: 'started', message: 'Running static probes' }));
      res.write(sseEvent({ type: 'lifecycle', status: 'DONE', message: 'done' }));
      res.end();
      return;
    }
    res.writeHead(404);
    res.end();
  };

  await withServer(handler, async (server) => {
    renderDetail(server);
    // live SSE event rendered by the ScanProgress component
    await waitFor(() => assert.ok(screen.getByText('Running static probes')));
    // terminal: re-fetched findings render in the report section
    await waitFor(() => assert.ok(screen.getByTestId('findings-section')));
    assert.ok(screen.getByText('System prompt leaked'));
    assert.ok(screen.getByTestId('scan-progress'));
  });
});

test('aborts the SSE connection on unmount (cleanup)', async () => {
  let streamClosed = false;
  const handler: TestHandler = (req: IncomingMessage, res: ServerResponse) => {
    if (req.url === `/scans/${SCAN_ID}`) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(detailJson('RUNNING')));
      return;
    }
    if (req.url === `/scans/${SCAN_ID}/stream`) {
      req.on('close', () => {
        streamClosed = true;
      });
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write(sseEvent({ type: 'stage', phase: 'layer-1', status: 'started', message: 'Probing' }));
      // keep the connection open — the client should abort it on unmount
      return;
    }
    res.writeHead(404);
    res.end();
  };

  await withServer(handler, async (server) => {
    renderDetail(server);
    await waitFor(() => assert.ok(screen.getByText('Probing')));
    cleanup(); // unmount → effect cleanup → controller.abort()
    await waitFor(() => assert.equal(streamClosed, true), { timeout: 3000 });
  });
});

test('an already-finished scan renders its findings without opening a stream', async () => {
  let streamHit = false;
  const finding = {
    id: 'f1',
    severity: 'CRITICAL',
    category: 'jailbreak',
    title: 'Jailbreak succeeded',
    description: 'The guardrails were bypassed.',
    evidence: { input: 'roleplay as…', output: 'sure, here is how…' },
    recommendation: 'Strengthen refusal policy.',
  };
  const handler: TestHandler = (req, res) => {
    if (req.url === `/scans/${SCAN_ID}/stream`) {
      streamHit = true;
    }
    if (req.url === `/scans/${SCAN_ID}`) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(detailJson('DONE', { findings: [finding] })));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end();
  };

  await withServer(handler, async (server) => {
    renderDetail(server);
    await waitFor(() => assert.ok(screen.getByText('Jailbreak succeeded')));
    assert.ok(screen.getByTestId('findings-section'));
    assert.equal(streamHit, false); // terminal at load → no SSE opened
  });
});

test('a missing/forbidden scan (404) shows a not-found state', async () => {
  const handler: TestHandler = (_req, res) => {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ statusCode: 404, message: 'Scan not found', error: 'Not Found' }));
  };

  await withServer(handler, async (server) => {
    renderDetail(server);
    await waitFor(() => assert.ok(screen.getByText('Scan not found')));
  });
});
