import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import { AuthGuard, type AuthenticatedRequest } from '../auth/auth.guard';

import { type UserProfileResponse } from './user.dto';
import { UserService } from './user.service';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UserService) {}

  @Get('me')
  @UseGuards(AuthGuard)
  async getMe(@Req() req: AuthenticatedRequest): Promise<UserProfileResponse> {
    return this.userService.getProfile(req.privyUser.userId);
  }
}
