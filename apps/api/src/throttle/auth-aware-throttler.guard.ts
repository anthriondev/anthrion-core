import { Injectable, type ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Request } from 'express';

import type { AuthenticatedRequest } from '../auth/auth.guard';

/**
 * Custom throttler guard (Phase 1.5 Sprint B1, T-B1.1).
 *
 * Why a subclass: the default `ThrottlerGuard` keys per IP. That is the right thing
 * for unauthenticated routes, but for authenticated routes it would let a single user
 * burn another user's quota through a shared NAT — and worse, would let multiple
 * accounts behind the same egress IP share a single quota that should be per-account.
 *
 * `getTracker` is invoked by the base `ThrottlerGuard` to choose the bucket key. We
 * use the Privy user id if the request has already passed `AuthGuard` (the auth guard
 * runs before this one — see `app.module.ts`), and fall back to the request IP for any
 * route that is intentionally public (e.g. health checks). This is the only deviation
 * from the upstream guard — every other behavior (header emission, exception flow,
 * `setHeaders`, named throttlers) comes from the base class unchanged.
 *
 * No `skipIf`-style global escape: the per-environment kill switch lives in the module
 * (`RATE_LIMIT_DISABLED` env). Putting it here too would split the logic in two places.
 */
@Injectable()
export class AuthAwareThrottlerGuard extends ThrottlerGuard {
  /** Per-request tracker key — user id when authenticated, IP otherwise. */
  protected override getTracker(req: Record<string, unknown>): Promise<string> {
    // The base class types `req` loosely; we narrow safely with runtime checks (CLAUDE.md
    // §3) — never `as Type` an untrusted shape. `privyUser` may be absent (unauthenticated
    // route, or this guard ran before AuthGuard for any reason); fall through to IP.
    const candidate = (req as Partial<AuthenticatedRequest>).privyUser;
    if (
      candidate !== undefined &&
      typeof candidate === 'object' &&
      candidate !== null &&
      typeof (candidate as { userId?: unknown }).userId === 'string' &&
      (candidate as { userId: string }).userId !== ''
    ) {
      return Promise.resolve(`user:${(candidate as { userId: string }).userId}`);
    }
    const ip = ipOf(req);
    return Promise.resolve(`ip:${ip}`);
  }

  /**
   * Discriminator the `scans` throttler uses via its `skipIf` (declared in
   * `throttle.module.ts`). Exposed as a static so the module's skipIf and any future
   * tests share one source of truth on what counts as "the scan creation route".
   */
  static isScanCreate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    if (req.method !== 'POST') return false;
    // Express stores the resolved route path on `req.route?.path` (e.g. `'/'` for the
    // root of a controller). The scans controller mounts at `scans`, so the resolved
    // path for `POST /scans` is `'/'`. We belt-and-braces with the URL too in case
    // route metadata is missing for any reason.
    const routePath = (req.route as { path?: string } | undefined)?.path;
    if (routePath === '/' || routePath === '/scans') {
      return true;
    }
    // Fallback: the URL path itself (without the query string) is `/scans` for this route.
    const url = req.originalUrl ?? req.url ?? '';
    return url === '/scans' || url.startsWith('/scans?');
  }
}

/** Extract the request IP without throwing. Express populates `req.ip` for us. */
function ipOf(req: Record<string, unknown>): string {
  const ip = (req as { ip?: unknown }).ip;
  if (typeof ip === 'string' && ip !== '') return ip;
  return 'unknown';
}
