import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';

import { type AuthTokenClaims } from './auth.types';
import { AuthService } from './auth.service';

export type AuthenticatedRequest = Request & { privyUser: AuthTokenClaims };

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const authHeader = request.headers['authorization'];

    if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing Bearer token');
    }

    const token = authHeader.slice(7);
    const claims = await this.authService.verifyToken(token);

    Object.assign(request, { privyUser: claims } satisfies { privyUser: AuthTokenClaims });

    return true;
  }
}
