import './test-dom';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { cleanup, render, screen, waitFor } from '@testing-library/react';

import { createScanApiClient } from '../../../lib/api-client';
import { startTestServer, type TestHandler, type TestServer } from '../../../lib/http-test-server';

import { ScansListScreen } from './ScansListScreen';

const getToken = (): Promise<string | null> => Promise.resolve('test-token');

function renderList(server: TestServer): void {
  const client = createScanApiClient({ baseUrl: server.url, getToken });
  render(<ScansListScreen client={client} />);
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

test('loads and renders the user scans from the real api client', async () => {
  const handler: TestHandler = (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        scans: [
          { id: 's1', status: 'RUNNING', scanType: 'ai-llm-attack', targetUrl: 'https://agent.example', createdAt: '2026-05-25T10:00:00.000Z', finishedAt: null },
          { id: 's2', status: 'DONE', scanType: 'web-app-vuln', targetUrl: 'https://site.example', createdAt: '2026-05-24T10:00:00.000Z', finishedAt: '2026-05-24T10:05:00.000Z' },
        ],
      }),
    );
  };

  await withServer(handler, async (server) => {
    renderList(server);
    await waitFor(() => assert.ok(screen.getByText('AI / LLM attack scan')));
    assert.ok(screen.getByText('Web app vulnerability scan'));
    const links = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    assert.ok(links.includes('/scans/s1'));
    assert.ok(links.includes('/scans/s2'));
  });
});

test('shows an error state when listScans fails', async () => {
  const handler: TestHandler = (_req, res) => {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ statusCode: 500, message: 'Internal error' }));
  };

  await withServer(handler, async (server) => {
    renderList(server);
    await waitFor(() => assert.ok(screen.getByTestId('list-error')));
  });
});

test('shows the empty state when the user has no scans', async () => {
  const handler: TestHandler = (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ scans: [] }));
  };

  await withServer(handler, async (server) => {
    renderList(server);
    await waitFor(() => assert.ok(screen.getByTestId('list-empty')));
  });
});
