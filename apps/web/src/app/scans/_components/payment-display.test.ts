import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  formatUsdcAtomic,
  networkLabel,
  paymentChipClasses,
  paymentKindLabel,
  paymentStatusLabel,
  shortWallet,
} from './payment-display';

test('paymentKindLabel maps each kind to honest copy', () => {
  assert.match(paymentKindLabel('FREE_PRICING'), /promotional/i);
  assert.equal(paymentKindLabel('FREE_TRIAL'), 'Free trial scan');
  assert.equal(paymentKindLabel('PAID'), 'Paid scan');
});

test('paymentStatusLabel maps each status', () => {
  assert.equal(paymentStatusLabel('PENDING'), 'Payment pending');
  assert.equal(paymentStatusLabel('SETTLED'), 'Paid');
  assert.equal(paymentStatusLabel('REFUND_PENDING'), 'Refund pending');
  assert.equal(paymentStatusLabel('REFUNDED'), 'Refunded');
  assert.equal(paymentStatusLabel('FAILED'), 'Payment failed');
});

test('paymentChipClasses uses a semantic tint only for PAID problem states', () => {
  assert.match(paymentChipClasses('PAID', 'FAILED'), /severity-medium/);
  assert.match(paymentChipClasses('PAID', 'REFUNDED'), /severity-medium/);
  // Normal/free states stay neutral (magenta/severity discipline).
  assert.doesNotMatch(paymentChipClasses('PAID', 'SETTLED'), /severity/);
  assert.doesNotMatch(paymentChipClasses('FREE_PRICING', 'SETTLED'), /severity/);
  assert.doesNotMatch(paymentChipClasses('FREE_TRIAL', 'SETTLED'), /severity/);
});

test('shortWallet truncates long addresses and leaves short ones', () => {
  assert.equal(shortWallet('0x1234567890abcdef1234'), '0x1234…1234');
  assert.equal(shortWallet('0xabcd'), '0xabcd');
});

test('networkLabel maps supported networks', () => {
  assert.equal(networkLabel('base'), 'Base');
  assert.equal(networkLabel('base-sepolia'), 'Base Sepolia');
});

test('formatUsdcAtomic converts atomic USDC (6 decimals) to a human amount', () => {
  assert.equal(formatUsdcAtomic('10000'), '0.01 USDC');
  assert.equal(formatUsdcAtomic('1000000'), '1 USDC');
  assert.equal(formatUsdcAtomic('1500000'), '1.5 USDC');
  assert.equal(formatUsdcAtomic('0'), '0 USDC');
  assert.equal(formatUsdcAtomic('1'), '0.000001 USDC');
});

test('formatUsdcAtomic is defensive against non-integer input (no trust-then-format)', () => {
  assert.match(formatUsdcAtomic('not-a-number'), /atomic USDC/);
});
