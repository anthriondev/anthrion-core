import {
  parsePaymentHeader,
  paymentRequirementsSchema,
  type PaymentPayload,
  type PaymentRequirements,
  type SettleResponse,
  type VerifyResponse,
} from '@anthrion/shared';

import type {
  BuildRequirementsInput,
  ChainAdapter,
  PaymentNetwork,
  RefundInput,
  RefundResult,
} from './chain-adapter';
import type { FacilitatorClient } from './facilitator-client';
import { PaymentNotConfiguredError } from './payment.errors';

export interface BaseChainAdapterConfig {
  network: Extract<PaymentNetwork, 'base' | 'base-sepolia'>;
  /** USDC contract on Base. */
  asset: string;
  /** Treasury address that receives USDC (x402 `payTo`). May be '' in Phase 1 (price 0). */
  payTo: string;
  maxTimeoutSeconds: number;
  facilitator: FacilitatorClient;
}

/**
 * Base (EVM) ChainAdapter — USDC `exact` scheme via EIP-3009 `transferWithAuthorization`.
 * The EIP-712 domain for USDC rides in `extra` ({ name, version }). verify/settle delegate to
 * the facilitator; refund is our own ERC-20 transfer (treasury → payer), unimplemented in T5.1
 * (needs the treasury key — boundary). USDC is 6-decimal; amounts are atomic strings.
 */
export class BaseChainAdapter implements ChainAdapter {
  constructor(private readonly config: BaseChainAdapterConfig) {}

  get network(): PaymentNetwork {
    return this.config.network;
  }

  get asset(): string {
    return this.config.asset;
  }

  buildPaymentRequirements({ amountAtomic, resource, description }: BuildRequirementsInput): PaymentRequirements {
    if (this.config.payTo === '') {
      // Treasury payTo not set (Phase 1 price is 0, so this is never reached). Configured with
      // the treasury wallet package before paid pricing is enabled. Boundary.
      throw new PaymentNotConfiguredError('payTo treasury address');
    }
    // Parse through the schema so what we advertise is exactly the validated wire shape.
    return paymentRequirementsSchema.parse({
      scheme: 'exact',
      network: this.config.network,
      maxAmountRequired: amountAtomic.toString(),
      resource,
      description,
      mimeType: 'application/json',
      payTo: this.config.payTo,
      maxTimeoutSeconds: this.config.maxTimeoutSeconds,
      asset: this.config.asset,
      extra: { name: 'USDC', version: '2' },
    });
  }

  parsePaymentPayload(header: string): PaymentPayload | undefined {
    return parsePaymentHeader(header);
  }

  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse> {
    return this.config.facilitator.verify(payload, requirements);
  }

  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse> {
    return this.config.facilitator.settle(payload, requirements);
  }

  refund(input: RefundInput): Promise<RefundResult> {
    void input;
    // Our own on-chain USDC transfer (treasury → payer). Needs the treasury key (separate
    // package). The CALL POINT exists (PaymentService.refundForFailedScan); execution is the
    // T5.1 boundary. x402 `exact` is irreversible push — there is no built-in refund.
    return Promise.reject(new PaymentNotConfiguredError('refund execution'));
  }
}
