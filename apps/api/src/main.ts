import 'reflect-metadata';

import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';

import { env } from '@anthrion/shared';

import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // Behind nginx on the same host (T-B1.3). Trust only the loopback proxy so
  // `req.ip` is the real client IP from X-Forwarded-For — without this the
  // rate limiter (T-B1.1) buckets everyone under 127.0.0.1. Loopback-only is
  // safe: a forged X-Forwarded-For from a remote attacker is dropped because
  // the immediate peer is the public IP, not 127.0.0.1.
  app.set('trust proxy', 'loopback');

  // Exact origin — never a wildcard (CLAUDE.md §3 + T-B1.4 plan: bearer tokens
  // cross the boundary). The value is env-driven so dev/staging/prod each set
  // their own without code change.
  app.enableCors({ origin: env.API_CORS_ORIGIN, credentials: false });

  // Run providers' onApplicationShutdown hooks (closes the scan-queue Redis connection).
  app.enableShutdownHooks();
  const port = process.env['PORT'] ?? 3001;
  const host = process.env['HOST'] ?? '127.0.0.1';
  await app.listen(port, host);
  console.log(`[api] running on ${host}:${port} (cors=${env.API_CORS_ORIGIN})`);
}

// Surface a startup failure (env validation, DB/Redis unreachable, port conflict) clearly
// and exit non-zero — never a silent termination (CLAUDE.md §3).
bootstrap().catch((error: unknown) => {
  console.error('[api] startup failed:', error);
  process.exit(1);
});
