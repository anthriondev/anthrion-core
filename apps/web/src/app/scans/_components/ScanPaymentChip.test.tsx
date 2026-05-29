import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { ScanPaymentChip } from './ScanPaymentChip';

test('renders the FREE_PRICING kind (the active Phase 1 path)', () => {
  const html = renderToStaticMarkup(<ScanPaymentChip payment={{ kind: 'FREE_PRICING', status: 'SETTLED' }} />);
  assert.match(html, /data-payment-kind="FREE_PRICING"/);
  assert.match(html, /Free scan \(promotional period\)/);
});

test('renders the FREE_TRIAL kind without a status suffix', () => {
  const html = renderToStaticMarkup(<ScanPaymentChip payment={{ kind: 'FREE_TRIAL', status: 'SETTLED' }} />);
  assert.match(html, /Free trial scan/);
  assert.doesNotMatch(html, /·/); // no status appended for free kinds
});

test('renders kind + status for a PAID scan', () => {
  const html = renderToStaticMarkup(<ScanPaymentChip payment={{ kind: 'PAID', status: 'SETTLED' }} />);
  assert.match(html, /data-payment-status="SETTLED"/);
  assert.match(html, /Paid scan/);
  assert.match(html, /Paid/);
});

test('a PAID failed status uses a semantic tint', () => {
  const html = renderToStaticMarkup(<ScanPaymentChip payment={{ kind: 'PAID', status: 'FAILED' }} />);
  assert.match(html, /Payment failed/);
  assert.match(html, /severity-medium/);
});

test('null payment renders an honest "no payment record" chip', () => {
  const html = renderToStaticMarkup(<ScanPaymentChip payment={null} />);
  assert.match(html, /data-payment-kind="none"/);
  assert.match(html, /No payment record/);
});
