import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';

import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { PaymentModule } from './payments/payment.module';
import { PrismaModule } from './prisma/prisma.module';
import { ScanModule } from './scans/scan.module';
import { AppThrottleModule } from './throttle/throttle.module';
import { UserModule } from './user/user.module';
import { UserSyncInterceptor } from './user/user-sync.interceptor';

@Module({
  imports: [
    // Rate limiter (T-B1.1) — must be present in the root module so its global
    // APP_GUARD applies to every controller. Module config is env-driven.
    AppThrottleModule,
    PrismaModule,
    AuthModule,
    UserModule,
    ScanModule,
    PaymentModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: UserSyncInterceptor,
    },
  ],
})
export class AppModule {}
