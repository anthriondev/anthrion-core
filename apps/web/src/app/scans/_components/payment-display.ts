import type { PaymentKindWire, PaymentStatusWire } from '@anthrion/shared/payment-api';
import type { X402Network } from '@anthrion/shared/x402';

/**
 * Pure display helpers for payment UI (T5.4). Kept DOM-free so labels/formatting are
 * unit-testable on their own (mirrors `scan-display.ts`). All copy is public-facing, so it
 * follows the disclosure rules (CLAUDE.md §7): it names the pay-per-scan model, the free trial
 * and the chain — never infrastructure or model internals.
 */

/**
 * Human label for HOW a scan was paid for (T5.4 Part 1). FREE_PRICING is the active Phase 1
 * path (global price 0, the promotional period); FREE_TRIAL is the one-per-wallet trial; PAID
 * is a real x402/USDC payment (relevant once paid pricing is switched on).
 */
export function paymentKindLabel(kind: PaymentKindWire): string {
  switch (kind) {
    case 'FREE_PRICING':
      return 'Free scan (promotional period)';
    case 'FREE_TRIAL':
      return 'Free trial scan';
    case 'PAID':
      return 'Paid scan';
  }
}

/** Human label for the payment lifecycle status. Only meaningful for PAID scans; FREE_* are
 * always SETTLED. */
export function paymentStatusLabel(status: PaymentStatusWire): string {
  switch (status) {
    case 'PENDING':
      return 'Payment pending';
    case 'SETTLED':
      return 'Paid';
    case 'REFUND_PENDING':
      return 'Refund pending';
    case 'REFUNDED':
      return 'Refunded';
    case 'FAILED':
      return 'Payment failed';
  }
}

/**
 * Chip classes for a payment kind/status. Payment metadata is shown in scan-result UI (not the
 * landing), so a restrained neutral chip by default; a problem PAID state (failed/refund) uses
 * a semantic tint, consistent with the severity discipline (DESIGN_SYSTEM.md §2).
 */
export function paymentChipClasses(kind: PaymentKindWire, status: PaymentStatusWire): string {
  if (kind === 'PAID' && (status === 'FAILED' || status === 'REFUND_PENDING' || status === 'REFUNDED')) {
    return 'border-severity-medium/40 text-severity-medium';
  }
  return 'border-trace text-text-secondary';
}

/** Truncate a wallet address for display: `0x1234…cdef`. Short inputs are returned as-is. */
export function shortWallet(address: string): string {
  if (address.length <= 12) {
    return address;
  }
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

/** Human label for a supported x402 network. */
export function networkLabel(network: X402Network): string {
  return network === 'base' ? 'Base' : 'Base Sepolia';
}

/**
 * Format an atomic-USDC integer string (6 decimals) as a human USDC amount, e.g. "10000" →
 * "0.01 USDC". Trailing zeros are trimmed; whole amounts show no decimals. Returns the raw
 * value with a unit if the input is not a clean integer string (defensive — the value is
 * validated server-side, but never trust-then-format).
 */
export function formatUsdcAtomic(atomic: string): string {
  if (!/^\d+$/.test(atomic)) {
    return `${atomic} (atomic USDC)`;
  }
  const padded = atomic.padStart(7, '0');
  const whole = padded.slice(0, -6);
  const fraction = padded.slice(-6).replace(/0+$/, '');
  const amount = fraction === '' ? whole : `${whole}.${fraction}`;
  return `${amount} USDC`;
}
