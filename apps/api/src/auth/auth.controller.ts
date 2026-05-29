import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import { AuthGuard, type AuthenticatedRequest } from './auth.guard';

@Controller('auth')
export class AuthController {
  @Get('me')
  @UseGuards(AuthGuard)
  getMe(@Req() req: AuthenticatedRequest): { userId: string; sessionId: string } {
    return {
      userId: req.privyUser.userId,
      sessionId: req.privyUser.sessionId,
    };
  }
}
