import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrivyClient } from '@privy-io/server-auth';

import { PRIVY_CLIENT } from './auth.constants';
import { type AuthTokenClaims, authTokenClaimsSchema } from './auth.types';

@Injectable()
export class AuthService {
  constructor(@Inject(PRIVY_CLIENT) private readonly privyClient: PrivyClient) {}

  async verifyToken(token: string): Promise<AuthTokenClaims> {
    let rawClaims: unknown;

    try {
      rawClaims = await this.privyClient.verifyAuthToken(token);
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    const parsed = authTokenClaimsSchema.safeParse(rawClaims);

    if (!parsed.success) {
      throw new UnauthorizedException('Malformed token claims');
    }

    return parsed.data;
  }
}
