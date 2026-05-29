import { Injectable } from '@nestjs/common';

import type { PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse } from '@anthrion/shared';

import { PaymentNotConfiguredError } from './payment.errors';

/**
 * Abstraction over the x402 facilitator's two operations (verify / settle). Concrete
 * implementations (CDP, self-hosted x402-rs, or in-process viem) plug in behind this — the
 * choice is deliberately NOT locked here (research done; user decides). verify/settle speak
 * the x402 wire shapes from `@anthrion/shared`.
 */
export interface FacilitatorClient {
  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse>;
  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse>;
}

/**
 * PLACEHOLDER facilitator (T5.1) — NOT FINAL. verify/settle reject with a clear
 * `PaymentNotConfiguredError`, so the PAID path is fully structured yet obviously unwired
 * (not a hidden mock). The FREE paths never call this. Replace this provider with the real
 * client once a facilitator is chosen and the treasury key store exists.
 */
@Injectable()
export class NotConfiguredFacilitatorClient implements FacilitatorClient {
  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse> {
    void payload;
    void requirements;
    return Promise.reject(new PaymentNotConfiguredError('facilitator.verify'));
  }

  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse> {
    void payload;
    void requirements;
    return Promise.reject(new PaymentNotConfiguredError('facilitator.settle'));
  }
}
