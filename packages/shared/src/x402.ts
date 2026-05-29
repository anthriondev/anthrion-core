import { z } from 'zod';

/**
 * x402 payment wire contract (T5.1) — the HTTP-402 payment shapes ANTHRION speaks.
 *
 * These MIRROR the types in the official `x402` package (v1.2.0, Apache-2.0) — read from
 * its published `dist/.../types/index.d.ts` — defined here independently as plain wire
 * data (the same approach `scan-job.ts` takes for the engine's target specs). We do NOT
 * depend on the `x402` runtime package yet: x402 1.2.0 pulls in `viem`, `wagmi` and the
 * Solana kit, which is far too heavy for the API and would prematurely lock a facilitator
 * (CLAUDE.md §6 / §8). The concrete facilitator + on-chain integration package (a later
 * step, once a facilitator + treasury key store is chosen) will import the real x402
 * helpers; these Zod schemas are the validation boundary until then (CLAUDE.md §3).
 *
 * Phase 1 focus is Base (EVM, USDC, EIP-3009 `exact`). Solana is added later behind its
 * own ChainAdapter; when it is, extend `x402NetworkSchema` and add an SVM payload schema.
 */

/** The x402 protocol version ANTHRION speaks (current x402 = 1). */
export const X402_VERSION = 1;

/** Only the `exact` scheme exists in x402 today. */
export const x402SchemeSchema = z.literal('exact');
export type X402Scheme = z.infer<typeof x402SchemeSchema>;

/**
 * Networks ANTHRION accepts in Phase 1 (Base only). The x402 package recognises many more;
 * we intentionally validate against the subset we have a ChainAdapter for, so a payload for
 * an unsupported chain is rejected clearly rather than silently accepted.
 */
export const x402NetworkSchema = z.enum(['base', 'base-sepolia']);
export type X402Network = z.infer<typeof x402NetworkSchema>;

/**
 * EIP-3009 `transferWithAuthorization` authorization the buyer signs (amounts are atomic
 * USDC, 6 decimals, as decimal strings — never floats). `validBefore` bounds the window
 * (x402 `maxTimeoutSeconds`, default 60s); `nonce` makes it single-use (anti-replay).
 */
export const exactEvmAuthorizationSchema = z.object({
  from: z.string().min(1),
  to: z.string().min(1),
  value: z.string().regex(/^\d+$/, 'value must be an atomic-unit integer string'),
  validAfter: z.string().regex(/^\d+$/),
  validBefore: z.string().regex(/^\d+$/),
  nonce: z.string().min(1),
});
export type ExactEvmAuthorization = z.infer<typeof exactEvmAuthorizationSchema>;

/** The EVM `exact` payload: the signed authorization + its signature. */
export const exactEvmPayloadSchema = z.object({
  signature: z.string().min(1),
  authorization: exactEvmAuthorizationSchema,
});
export type ExactEvmPayload = z.infer<typeof exactEvmPayloadSchema>;

/** The full payment payload a client sends (base64-encoded in the `X-PAYMENT` header). */
export const paymentPayloadSchema = z.object({
  x402Version: z.number().int().positive(),
  scheme: x402SchemeSchema,
  network: x402NetworkSchema,
  payload: exactEvmPayloadSchema,
});
export type PaymentPayload = z.infer<typeof paymentPayloadSchema>;

/**
 * What the server advertises in its 402 response (the `accepts` entry). `maxAmountRequired`
 * and `asset` are atomic USDC + the USDC contract; `payTo` is our treasury address.
 */
export const paymentRequirementsSchema = z.object({
  scheme: x402SchemeSchema,
  network: x402NetworkSchema,
  maxAmountRequired: z.string().regex(/^\d+$/),
  resource: z.string().min(1),
  description: z.string(),
  mimeType: z.string(),
  payTo: z.string().min(1),
  maxTimeoutSeconds: z.number().int().positive(),
  asset: z.string().min(1),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  extra: z.record(z.string(), z.unknown()).optional(),
});
export type PaymentRequirements = z.infer<typeof paymentRequirementsSchema>;

/**
 * The body of an HTTP 402 (`Payment Required`) response. Mirrors the x402 spec's 402 shape:
 * `accepts` lists the payment options the server will honour, `error` is an optional
 * human-readable reason. A client (browser OR AI agent) reads `accepts`, pays one option, and
 * retries the request with the `X-PAYMENT` header. 402 is a NORMAL part of the protocol, not a
 * failure (BUSINESS_MODEL.md, ARCHITECTURE.md §8) — it is the foundation of the Phase 1.5
 * agent API. The server Zod-validates this body before sending it (the response is our own
 * data, but validating keeps the advertised wire shape honest — same boundary discipline as
 * everywhere else, CLAUDE.md §3).
 */
export const paymentRequiredResponseSchema = z.object({
  x402Version: z.number().int().positive(),
  accepts: z.array(paymentRequirementsSchema).min(1),
  error: z.string().optional(),
});
export type PaymentRequiredResponse = z.infer<typeof paymentRequiredResponseSchema>;

/** Facilitator `/verify` response. */
export const verifyResponseSchema = z.object({
  isValid: z.boolean(),
  invalidReason: z.string().optional(),
  payer: z.string().optional(),
});
export type VerifyResponse = z.infer<typeof verifyResponseSchema>;

/** Facilitator `/settle` response — `txHash` is the on-chain proof we persist. */
export const settleResponseSchema = z.object({
  success: z.boolean(),
  errorReason: z.string().optional(),
  txHash: z.string().optional(),
  network: x402NetworkSchema.optional(),
  payer: z.string().optional(),
});
export type SettleResponse = z.infer<typeof settleResponseSchema>;

/**
 * Decode + validate an `X-PAYMENT` header (base64 JSON) into a `PaymentPayload`. Returns
 * `undefined` for anything malformed — callers treat it as "no valid payment" rather than
 * trusting raw input (CLAUDE.md §3). Never throws.
 */
export function parsePaymentHeader(header: string): PaymentPayload | undefined {
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
  } catch {
    return undefined;
  }
  const parsed = paymentPayloadSchema.safeParse(json);
  return parsed.success ? parsed.data : undefined;
}
