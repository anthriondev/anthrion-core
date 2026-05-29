import type {
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  VerifyResponse,
  X402Network,
} from '@anthrion/shared';

export type PaymentNetwork = X402Network;

export interface BuildRequirementsInput {
  /** Price in atomic USDC units (6 decimals). */
  amountAtomic: bigint;
  /** The resource being paid for (the scan), e.g. `/scans/<id>` — x402 `resource`. */
  resource: string;
  description: string;
}

export interface RefundInput {
  paymentId: string;
  network: string;
  asset: string;
  amountAtomic: string;
  /** Payer wallet to refund to. */
  to: string;
}

export interface RefundResult {
  txHash: string;
}

/**
 * Per-chain payment operations (T5.1). Base (EVM / EIP-3009) is implemented now; Solana
 * (SVM, push model) is a SEPARATE adapter later — locked decision "Base first". `PaymentService`
 * depends only on this interface, so adding a chain doesn't change the flow (Target Adapter
 * pattern, T2.2).
 *
 * `verify`/`settle` delegate to the facilitator. `refund` is OUR own logic — x402 `exact` is an
 * irreversible push payment with no built-in refund (billing mechanism A). Both are placeholders
 * in T5.1 until a facilitator + treasury key store exist.
 */
export interface ChainAdapter {
  readonly network: PaymentNetwork;
  /** USDC contract/mint on this network. */
  readonly asset: string;
  buildPaymentRequirements(input: BuildRequirementsInput): PaymentRequirements;
  /** Decode + Zod-validate an `X-PAYMENT` header; `undefined` if malformed. */
  parsePaymentPayload(header: string): PaymentPayload | undefined;
  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse>;
  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse>;
  refund(input: RefundInput): Promise<RefundResult>;
}
