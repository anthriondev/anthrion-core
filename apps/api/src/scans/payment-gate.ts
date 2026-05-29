import { Injectable } from '@nestjs/common';

import { PaymentService, type AuthorizeScanInput, type PaymentOutcome } from '../payments/payment.service';

/**
 * Payment gate — the integration seam between scan orchestration and the payment layer.
 *
 * T4.1 shipped this as an allow-all PLACEHOLDER (the documented hook where the pay gate plugs
 * in). T5.2 makes it real: it now delegates to `PaymentService.authorizeScan` (T5.1) — the same
 * x402-native path the Phase 1.5 agent API will reuse — instead of letting every scan through.
 *
 * The gate is intentionally THIN. It answers one question — "is this scan paid for?" — and
 * returns the typed {@link PaymentOutcome} (or lets the payment layer's domain errors propagate:
 * `PaymentInvalidError` for a broken payment, `PaymentNotConfiguredError` at the facilitator
 * boundary). The Scan-record lifecycle (create / discard / enqueue / refund-on-failure) stays
 * in `ScanService`, which owns it; keeping it out of the gate avoids two places mutating scans.
 */
@Injectable()
export class PaymentGate {
  constructor(private readonly payments: PaymentService) {}

  /**
   * Verify payment for a scan BEFORE it is enqueued (ARCHITECTURE.md §8). The `scanId` must
   * already exist — the recorded `Payment` references it (FK). Returns:
   *  - `free-pricing` / `paid` → a `Payment` has been recorded & linked; the caller proceeds.
   *  - `payment-required` → no `Payment`; the caller answers HTTP 402 with `requirements`.
   * Throws `PaymentInvalidError` (malformed/failed payment) or `PaymentNotConfiguredError`
   * (facilitator not yet wired — the T5.1 boundary).
   */
  authorizeScan(input: AuthorizeScanInput): Promise<PaymentOutcome> {
    return this.payments.authorizeScan(input);
  }

  /**
   * Refund a captured PAID payment whose scan cannot run (e.g. enqueue failed after settle), so
   * a settled payment never bills a scan that won't execute. No-op for FREE_* (nothing charged).
   * Execution is the T5.1 boundary (needs the treasury key).
   */
  refundForFailedScan(scanId: string): Promise<void> {
    return this.payments.refundForFailedScan(scanId);
  }
}
