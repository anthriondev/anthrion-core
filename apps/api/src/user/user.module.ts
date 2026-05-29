import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';

import { UserSyncInterceptor } from './user-sync.interceptor';
import { UsersController } from './user.controller';
import { UserService } from './user.service';

@Module({
  imports: [AuthModule],
  controllers: [UsersController],
  providers: [UserService, UserSyncInterceptor],
  exports: [UserService, UserSyncInterceptor],
})
export class UserModule {}
