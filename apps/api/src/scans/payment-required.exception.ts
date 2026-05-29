import { HttpException, HttpStatus } from '@nestjs/common';

import type { PaymentRequiredResponse } from '@anthrion/shared';

/**
 * HTTP 402 Payment Required — the x402-native response of `POST /scans` when a priced scan
 * arrives without a settled payment (T5.2).
 *
 * This is NOT an error path: the body carries the x402 `PaymentRequirements` (`accepts`) the
 * caller pays, then retries the request with the `X-PAYMENT` header. It is the same structured
 * 402 a browser or an autonomous AI agent consumes (BUSINESS_MODEL.md; the foundation of the
 * Phase 1.5 pay-gated agent API). Carrying it as an `HttpException` lets NestJS serialise the
 * validated body with the correct 402 status without any custom filter.
 */
export class PaymentRequiredException extends HttpException {
  constructor(body: PaymentRequiredResponse) {
    super(body, HttpStatus.PAYMENT_REQUIRED);
  }
}
