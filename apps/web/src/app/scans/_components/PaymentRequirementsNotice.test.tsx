import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { PaymentRequiredResponse } from '@anthrion/shared/x402';

import { PaymentRequirementsNotice } from './PaymentRequirementsNotice';

const sample: PaymentRequiredResponse = {
  x402Version: 1,
  accepts: [
    {
      scheme: 'exact',
      network: 'base',
      maxAmountRequired: '10000',
      resource: '/scans/scan_1',
      description: 'ANTHRION security scan',
      mimeType: 'application/json',
      payTo: '0xTreasury0000000000000000000000000000beef',
      maxTimeoutSeconds: 60,
      asset: '0xUSDC00000000000000000000000000000000cafe',
    },
  ],
  error: 'Payment required to run this scan',
};

test('shows the x402 requirements honestly (amount, network, payTo)', () => {
  const html = renderToStaticMarkup(<PaymentRequirementsNotice paymentRequired={sample} />);
  assert.match(html, /data-testid="payment-requirements-notice"/);
  assert.match(html, /0.01 USDC on Base/);
  assert.match(html, /0xTreasury0000000000000000000000000000beef/);
});

test('clearly states paid scans are not active yet and awaits the facilitator', () => {
  const html = renderToStaticMarkup(<PaymentRequirementsNotice paymentRequired={sample} />);
  assert.match(html, /not active yet/i);
  assert.match(html, /facilitator/i);
});

test('there is NO pay button — it never misleads the user into paying', () => {
  const html = renderToStaticMarkup(<PaymentRequirementsNotice paymentRequired={sample} />);
  assert.doesNotMatch(html, /<button/i);
  assert.doesNotMatch(html, /\bpay now\b/i);
});
