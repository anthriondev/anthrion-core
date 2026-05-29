import { Module, type ExecutionContext } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';

import { env } from '@anthrion/shared';

import { AuthAwareThrottlerGuard } from './auth-aware-throttler.guard';

/**
 * API rate limiting (Phase 1.5 Sprint B1, T-B1.1).
 *
 * Two named throttlers (limits live in env, never hardcoded — see env.ts):
 *  - `default` (per IP): broad burst cap on every route, prevents accidental
 *    client loops / casual abuse.
 *  - `scans`   (per identity-or-IP): strict cap on `POST /scans` — that route
 *    is the only one that triggers real LLM cost (OpenRouter) and on
 *    free-pricing it must not be drainable. `skipIf` is the discriminator that
 *    keeps the `scans` throttler scoped to the scan-creation route alone;
 *    every other route only hits `default`.
 *
 * `RATE_LIMIT_DISABLED=true` skips ALL enforcement — an explicit, env-driven
 * escape hatch for test runs and local benchmarks. Never set true in prod.
 *
 * The guard is registered globally via `APP_GUARD`. Order matters: NestJS runs
 * `AuthGuard` (per controller) before global guards on protected routes, so by
 * the time `AuthAwareThrottlerGuard` reads `req.privyUser` the auth guard has
 * already populated it — the tracker becomes the user id rather than the IP.
 * On unauthenticated routes the tracker falls back to IP cleanly.
 */
@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      useFactory: () => ({
        // Module-level kill switch — applies to BOTH throttlers below. Honest:
        // when off, the value is loud (an explicit `true` in env) and not the
        // default; production cannot turn the limits off silently.
        skipIf: () => env.RATE_LIMIT_DISABLED,
        throttlers: [
          {
            name: 'default',
            limit: env.RATE_LIMIT_DEFAULT_PER_MINUTE,
            ttl: 60_000,
          },
          {
            name: 'scans',
            limit: env.RATE_LIMIT_SCANS_PER_HOUR,
            ttl: 60 * 60 * 1000,
            // `scans` runs only on the scan-create route; for everything else
            // it is skipped, so list/detail/SSE etc. only hit `default`. The
            // discriminator lives on the guard so it is one source of truth.
            skipIf: (ctx: ExecutionContext) => !AuthAwareThrottlerGuard.isScanCreate(ctx),
          },
        ],
      }),
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthAwareThrottlerGuard,
    },
  ],
})
export class AppThrottleModule {}
