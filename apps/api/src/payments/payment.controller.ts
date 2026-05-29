import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import type { FreeTrialStatusResponse } from '@anthrion/shared';

import { AuthGuard, type AuthenticatedRequest } from '../auth/auth.guard';

import { PaymentService } from './payment.service';

/**
 * Payment read endpoints for the UI (T5.4).
 *
 * Only the FREE-path, non-sensitive reads live here. The paid x402 transaction flow is NOT an
 * endpoint of its own: `POST /scans` already speaks x402 (201 / 402) per T5.2, and the actual
 * verify/settle is the facilitator boundary (PaymentService / NotConfiguredFacilitatorClient).
 *
 * Every route is protected by `AuthGuard`; the service resolves the authenticated account from
 * `req.privyUser.userId`, so a caller can only ever read its OWN status (Part C authorization).
 */
@Controller('payments')
@UseGuards(AuthGuard)
export class PaymentsController {
  constructor(private readonly payments: PaymentService) {}

  /**
   * GET /payments/free-trial — whether the current user's primary wallet still has its one-time
   * free trial (T5.4 Part 2). Read-only; the response is Zod-validated in the service.
   */
  @Get('free-trial')
  getFreeTrialStatus(@Req() req: AuthenticatedRequest): Promise<FreeTrialStatusResponse> {
    return this.payments.getFreeTrialStatus(req.privyUser.userId);
  }
}
