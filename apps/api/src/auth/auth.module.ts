import { Module } from '@nestjs/common';
import { PrivyClient } from '@privy-io/server-auth';

import { env } from '@anthrion/shared';

import { PRIVY_CLIENT } from './auth.constants';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  providers: [
    {
      provide: PRIVY_CLIENT,
      useFactory: (): PrivyClient => new PrivyClient(env.PRIVY_APP_ID, env.PRIVY_APP_SECRET),
    },
    AuthService,
  ],
  controllers: [AuthController],
  exports: [AuthService, PRIVY_CLIENT],
})
export class AuthModule {}
