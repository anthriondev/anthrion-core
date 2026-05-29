import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { Request } from 'express';
import { Observable, from, switchMap } from 'rxjs';

import type { AuthTokenClaims } from '../auth/auth.types';

import { UserService } from './user.service';

type MaybeAuthenticatedRequest = Request & { privyUser?: AuthTokenClaims };

@Injectable()
export class UserSyncInterceptor implements NestInterceptor {
  constructor(private readonly userService: UserService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<MaybeAuthenticatedRequest>();

    if (request.privyUser !== undefined) {
      return from(this.userService.syncUser(request.privyUser.userId)).pipe(
        switchMap(() => next.handle()),
      );
    }

    return next.handle();
  }
}
