import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { PaymentModule } from '../payments/payment.module';

import { ArtifactStorageService } from './artifact-storage.service';
import { PaymentGate } from './payment-gate';
import { ScanOwnerGuard } from './scan-owner.guard';
import { ScanStreamService } from './scan-stream.service';
import { scanQueueProducerProvider, ScanQueueShutdown } from './scan-queue.providers';
import { ScansController } from './scan.controller';
import { ScanService } from './scan.service';

/**
 * Scan orchestration module (T4.1). Imports AuthModule for the AuthGuard's AuthService and
 * PaymentModule for the PaymentService behind the real pay gate (T5.2). PrismaModule is
 * @Global, so PrismaService is available without importing it.
 */
@Module({
  imports: [AuthModule, PaymentModule],
  controllers: [ScansController],
  providers: [
    ScanService,
    ScanStreamService,
    ScanOwnerGuard,
    ArtifactStorageService,
    PaymentGate,
    scanQueueProducerProvider,
    ScanQueueShutdown,
  ],
})
export class ScanModule {}
