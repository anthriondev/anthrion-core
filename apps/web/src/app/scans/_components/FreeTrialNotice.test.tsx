import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { FreeTrialNotice } from './FreeTrialNotice';

test('available state shows "Free trial available" with the wallet', () => {
  const html = renderToStaticMarkup(
    <FreeTrialNotice state={{ kind: 'available', walletAddress: '0x1234567890abcdef1234' }} />,
  );
  assert.match(html, /data-trial-state="available"/);
  assert.match(html, /Free trial available/);
  assert.match(html, /0x1234…1234/);
});

test('used state shows "Free trial used" and points to paid scans', () => {
  const html = renderToStaticMarkup(
    <FreeTrialNotice state={{ kind: 'used', walletAddress: '0x1234567890abcdef1234' }} />,
  );
  assert.match(html, /data-trial-state="used"/);
  assert.match(html, /Free trial used/);
  assert.match(html, /paid per scan/i);
});

test('no-wallet state is honest and links to wallet management (not silence)', () => {
  const html = renderToStaticMarkup(<FreeTrialNotice state={{ kind: 'no-wallet' }} />);
  assert.match(html, /data-trial-state="no-wallet"/);
  assert.match(html, /Link a wallet/i);
  assert.match(html, /href="\/profile"/);
});

test('loading and error states are both shown (no silent gap)', () => {
  const loading = renderToStaticMarkup(<FreeTrialNotice state={{ kind: 'loading' }} />);
  assert.match(loading, /Checking free trial/i);

  const error = renderToStaticMarkup(<FreeTrialNotice state={{ kind: 'error', message: 'api down' }} />);
  assert.match(error, /data-trial-state="error"/);
  assert.match(error, /api down/);
});
