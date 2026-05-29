import { z } from 'zod';

/**
 * Payment-status wire contract (T5.4) — the non-sensitive payment shapes the web UI reads.
 *
 * Lives in `shared` (ARCHITECTURE.md §2 — the home for cross-app contracts) for the same
 * reason as `scan-api.ts`: `apps/api` produces these and `apps/web` consumes them, and the
 * two apps must not import each other. Runtime dependency is `zod` only, so it is safe to
 * import from `apps/web` via the `@anthrion/shared/payment-api` SUBPATH (never the barrel,
 * which pulls in `bullmq`) — mirroring how `scan-api`/`x402` are consumed.
 *
 * These mirror the Prisma `PaymentKind` / `PaymentStatus` enums (T5.1). The DB casing IS the
 * wire casing (like `ScanStatus`), so the api maps straight through with no enum remap; the
 * schema is still the validation boundary on both ends (CLAUDE.md §3).
 *
 * SECURITY: only `kind` + `status` cross the wire — never the raw x402 payload, signatures,
 * tx hashes or any on-chain proof columns (CLAUDE.md §7). This is "how was it paid for",
 * not the payment instrument.
 */

/** How a scan was paid for (matches Prisma `PaymentKind`). */
export const paymentKindWireSchema = z.enum(['PAID', 'FREE_TRIAL', 'FREE_PRICING']);
export type PaymentKindWire = z.infer<typeof paymentKindWireSchema>;

/** Payment lifecycle status (matches Prisma `PaymentStatus`). */
export const paymentStatusWireSchema = z.enum([
  'PENDING',
  'SETTLED',
  'REFUND_PENDING',
  'REFUNDED',
  'FAILED',
]);
export type PaymentStatusWire = z.infer<typeof paymentStatusWireSchema>;

/**
 * The payment summary attached to a scan (T5.4 Part 1). Just enough to honestly show HOW a
 * scan was paid for and its lifecycle status — no on-chain payload. A scan can momentarily
 * have no payment (the pre-commit window in `ScanService`), so consumers treat it as nullable.
 */
export const scanPaymentInfoSchema = z.object({
  kind: paymentKindWireSchema,
  status: paymentStatusWireSchema,
});
export type ScanPaymentInfo = z.infer<typeof scanPaymentInfoSchema>;

/**
 * Free-trial availability for the current user's primary wallet (T5.3 → T5.4 Part 2). Three
 * honest states the UI renders directly:
 *  - `available` — the wallet's one-time free trial has not been used (and no trial is in flight).
 *  - `used`      — the trial has been consumed (a FREE_TRIAL scan that is DONE) or is in flight.
 *  - `no-wallet` — the account has no linked wallet, so it is not trial-eligible (the trial binds
 *                  to a wallet — BUSINESS_MODEL.md); the UI prompts the user to link one.
 *
 * Independent of the current price: with FREE_PRICING (price 0) every scan is free and the trial
 * "sleeps" untouched, so a wallet that has only run promotional free scans still reads `available`.
 */
export const freeTrialStatusSchema = z.enum(['available', 'used', 'no-wallet']);
export type FreeTrialStatus = z.infer<typeof freeTrialStatusSchema>;

/** Response of `GET /payments/free-trial` (T5.4 Part 2). `walletAddress` is the user's own
 * public address (null when no wallet is linked) — shown so the user can see which wallet the
 * trial is bound to. */
export const freeTrialStatusResponseSchema = z.object({
  status: freeTrialStatusSchema,
  walletAddress: z.string().nullable(),
});
export type FreeTrialStatusResponse = z.infer<typeof freeTrialStatusResponseSchema>;
