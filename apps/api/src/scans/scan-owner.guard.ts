import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

import { type AuthenticatedRequest } from '../auth/auth.guard';

import { ScanService } from './scan.service';

/**
 * Authorizes access to a scan by id for the authenticated user (T4.2). Runs BEFORE the
 * `@Sse` handler so a non-owner / missing scan gets a clean 404 (no existence leak)
 * rather than an already-open SSE stream. Throws `NotFoundException` via the service.
 */
@Injectable()
export class ScanOwnerGuard implements CanActivate {
  constructor(private readonly scanService: ScanService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest & { params: { id: string } }>();
    // Throws 404 if the scan does not exist or is not owned by this user.
    await this.scanService.getOwnedScanStatus(request.privyUser.userId, request.params.id);
    return true;
  }
}
