import './test-dom';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { cleanup, render, screen, waitFor } from '@testing-library/react';

import { createScanApiClient } from '../../../lib/api-client';
import { startTestServer, type TestServer } from '../../../lib/http-test-server';

import { FreeTrialBanner } from './FreeTrialBanner';

const getToken = (): Promise<string | null> => Promise.resolve('test-token');

/** Render FreeTrialBanner against a real local server that returns `response` for the
 * `GET /payments/free-trial` call — exercising the real fetch + Zod path (CLAUDE.md §4). */
async function withBanner(
  response: { status: number; json: unknown },
  fn: () => Promise<void>,
): Promise<void> {
  let server: TestServer | undefined;
  server = await startTestServer((req, res) => {
    assert.equal(req.url, '/payments/free-trial');
    res.writeHead(response.status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(response.json));
  });
  const client = createScanApiClient({ baseUrl: server.url, getToken });
  render(<FreeTrialBanner client={client} />);
  try {
    await fn();
  } finally {
    cleanup();
    await server.close();
  }
}

test('renders the available state from a real GET /payments/free-trial', async () => {
  await withBanner(
    { status: 200, json: { status: 'available', walletAddress: '0x1234567890abcdef1234' } },
    async () => {
      await waitFor(() => assert.equal(screen.getByTestId('free-trial-notice').dataset['trialState'], 'available'));
      assert.match(screen.getByTestId('free-trial-notice').textContent ?? '', /Free trial available/);
    },
  );
});

test('renders the used state', async () => {
  await withBanner(
    { status: 200, json: { status: 'used', walletAddress: '0x1234567890abcdef1234' } },
    async () => {
      await waitFor(() => assert.equal(screen.getByTestId('free-trial-notice').dataset['trialState'], 'used'));
    },
  );
});

test('renders the no-wallet state', async () => {
  await withBanner({ status: 200, json: { status: 'no-wallet', walletAddress: null } }, async () => {
    await waitFor(() => assert.equal(screen.getByTestId('free-trial-notice').dataset['trialState'], 'no-wallet'));
  });
});

test('surfaces an error (e.g. 401) instead of failing silently', async () => {
  await withBanner(
    { status: 401, json: { statusCode: 401, message: 'Unauthorized', error: 'Unauthorized' } },
    async () => {
      await waitFor(() => assert.equal(screen.getByTestId('free-trial-notice').dataset['trialState'], 'error'));
    },
  );
});
