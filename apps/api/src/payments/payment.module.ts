import { Module } from '@nestjs/common';

import { env } from '@anthrion/shared';

import { AuthModule } from '../auth/auth.module';

import { BaseChainAdapter } from './base-chain-adapter';
import { NotConfiguredFacilitatorClient, type FacilitatorClient } from './facilitator-client';
import { PaymentsController } from './payment.controller';
import { ACTIVE_CHAIN_ADAPTER, FACILITATOR_CLIENT } from './payment.constants';
import { PaymentService } from './payment.service';
import { ScanPricing } from './pricing';

/**
 * Payment layer module (T5.1). Wires the env-driven price, the placeholder facilitator, and
 * the Base ChainAdapter behind `PaymentService`. PrismaService comes from the global
 * PrismaModule.
 *
 * BOUNDARY: `FACILITATOR_CLIENT` is the placeholder (`NotConfiguredFacilitatorClient`) and the
 * Base adapter's `payTo` is empty until paid pricing is enabled — swap/configure these in the
 * facilitator + treasury wallet package. With the Phase 1 default price 0, none of that is
 * exercised: the FREE_PRICING path runs fully.
 */
@Module({
  // AuthModule provides the AuthService the AuthGuard needs for PaymentsController (T5.4).
  imports: [AuthModule],
  controllers: [PaymentsController],
  providers: [
    PaymentService,
    { provide: FACILITATOR_CLIENT, useClass: NotConfiguredFacilitatorClient },
    { provide: ScanPricing, useFactory: (): ScanPricing => new ScanPricing(env.SCAN_PRICE_USDC_ATOMIC) },
    {
      provide: ACTIVE_CHAIN_ADAPTER,
      useFactory: (facilitator: FacilitatorClient): BaseChainAdapter =>
        new BaseChainAdapter({
          network: 'base',
          asset: env.PAYMENT_USDC_BASE_ADDRESS,
          payTo: env.PAYMENT_PAYTO_BASE_ADDRESS,
          maxTimeoutSeconds: 60,
          facilitator,
        }),
      inject: [FACILITATOR_CLIENT],
    },
  ],
  exports: [PaymentService],
})
export class PaymentModule {}
