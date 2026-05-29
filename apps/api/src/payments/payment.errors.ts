/**
 * Payment errors (T5.1).
 *
 * `PaymentNotConfiguredError` marks an explicit T5.1 BOUNDARY — a step that needs a concrete
 * facilitator and/or treasury wallet + keys, which are a separate package delivered before
 * paid pricing is enabled. It is thrown by the placeholder facilitator and the refund / payTo
 * paths so the PAID flow is structurally complete and obviously unwired (not a hidden mock —
 * same pattern as `LlmCaller` T2.2 / `PaymentGate` T4.1).
 *
 * `PaymentInvalidError` is a REAL rejection (malformed / failed / insufficient payment). T5.2
 * maps it to an HTTP 402/400 at `POST /scans`.
 */
export class PaymentNotConfiguredError extends Error {
  constructor(part: string) {
    super(
      `Payment not configured: "${part}" needs a concrete facilitator / treasury wallet — ` +
        'delivered before paid pricing is enabled (T5.1 boundary).',
    );
    this.name = 'PaymentNotConfiguredError';
  }
}

export class PaymentInvalidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PaymentInvalidError';
  }
}
