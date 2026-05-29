/**
 * Rate-limit enforcement tests (Phase 1.5 Sprint B1, T-B1.1).
 *
 * The general suite runs with `RATE_LIMIT_DISABLED=true` (see jest.setup.ts) so
 * existing controller integration tests are not affected. This spec FORCES the
 * limiter on with small numbers BEFORE the env module is loaded — that is the
 * only way to prove enforcement honestly (`CLAUDE.md` §3: tests must verify the
 * thing actually works, not just that the config exists).
 */

// MUST run before any `import` that loads `@anthrion/shared` and freezes env.
process.env['RATE_LIMIT_DISABLED'] = 'false';
process.env['RATE_LIMIT_DEFAULT_PER_MINUTE'] = '3';
process.env['RATE_LIMIT_SCANS_PER_HOUR'] = '2';

import { Controller, Get, INestApplication, Module, Post } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import request from 'supertest';

import { AuthAwareThrottlerGuard } from './auth-aware-throttler.guard';
import { AppThrottleModule } from './throttle.module';

/**
 * Stand-in controller: minimal surface for testing the throttler.
 *  - GET  /ping   → catches the `default` per-IP throttler.
 *  - POST /scans  → catches the strict `scans` per-identity throttler. (Path
 *    must literally be `/scans` because the throttler `skipIf` matches by URL
 *    when there is no global Auth context to set `privyUser`.)
 *  - GET  /scans  → must NOT be limited by `scans` (different method/route shape).
 */
@Controller()
class TestController {
  @Get('ping')
  ping(): { ok: true } {
    return { ok: true };
  }

  @Post('scans')
  createScan(): { created: true } {
    return { created: true };
  }

  @Get('scans')
  listScans(): { items: number[] } {
    return { items: [] };
  }
}

@Module({
  imports: [AppThrottleModule],
  controllers: [TestController],
})
class TestAppModule {}

describe('Rate limiting (T-B1.1)', () => {
  let app: INestApplication;
  let server: ReturnType<INestApplication['getHttpServer']>;

  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [TestAppModule],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
    server = app.getHttpServer();
  });

  afterEach(async () => {
    await app.close();
  });

  // Each test runs in its own app instance (new throttler storage), so requests
  // from one test do not leak quota into the next. Using a stable, distinct
  // `X-Forwarded-For` is unnecessary — `req.ip` differs by test app process,
  // but the throttler storage is fresh anyway.

  it('default throttler allows up to the per-minute limit, then returns 429', async () => {
    // Limit is 3 (env above); the 4th request hits the cap.
    await request(server).get('/ping').expect(200);
    await request(server).get('/ping').expect(200);
    await request(server).get('/ping').expect(200);
    const res = await request(server).get('/ping').expect(429);
    // 429 carries a body — Nest's default throttler exception. Honest, not a
    // generic 500 / opaque 503 / silent drop.
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ statusCode: 429 });
    expect(typeof res.body.message).toBe('string');
  });

  it('scans throttler enforces the per-hour cap on POST /scans only', async () => {
    // Per-hour limit is 2; the 3rd POST /scans returns 429.
    await request(server).post('/scans').send({}).expect(201);
    await request(server).post('/scans').send({}).expect(201);
    await request(server).post('/scans').send({}).expect(429);
  });

  it('GET /scans is NOT limited by the strict `scans` throttler (only `default` applies)', async () => {
    // The default throttler allows 3/min; making 3 GET /scans must succeed and
    // 3 POST /scans + 3 GET /scans should not interact: posts trip `scans`
    // long before GETs ever exhaust `default`.
    await request(server).get('/scans').expect(200);
    await request(server).get('/scans').expect(200);
    await request(server).get('/scans').expect(200);
    // 4th GET hits the DEFAULT cap, not the scans cap.
    await request(server).get('/scans').expect(429);
  });

  it('429 response carries Retry-After-ish standard headers (RateLimit-* set by the throttler)', async () => {
    await request(server).get('/ping').expect(200);
    await request(server).get('/ping').expect(200);
    await request(server).get('/ping').expect(200);
    const res = await request(server).get('/ping').expect(429);
    // The throttler emits at minimum the standard rate-limit headers; the exact
    // names may vary across versions but the policy/limit one is always set
    // when `setHeaders` defaults are in play. Make this assertion resilient:
    // at least ONE rate-limit header must be present on the 429.
    const headerNames = Object.keys(res.headers).filter((h) => h.toLowerCase().startsWith('x-ratelimit') || h.toLowerCase().startsWith('ratelimit') || h.toLowerCase() === 'retry-after');
    expect(headerNames.length).toBeGreaterThan(0);
  });
});

describe('AuthAwareThrottlerGuard.isScanCreate (discriminator)', () => {
  function ctxFor(method: string, routePath: string | undefined, url: string): Parameters<typeof AuthAwareThrottlerGuard.isScanCreate>[0] {
    const req = { method, route: routePath !== undefined ? { path: routePath } : undefined, originalUrl: url, url } as Record<string, unknown>;
    return {
      switchToHttp: () => ({ getRequest: () => req }),
    } as unknown as Parameters<typeof AuthAwareThrottlerGuard.isScanCreate>[0];
  }

  it('matches POST to the scans-create route (whether route.path is "/" or "/scans")', () => {
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('POST', '/', '/scans'))).toBe(true);
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('POST', '/scans', '/scans'))).toBe(true);
  });

  it('does NOT match non-POST requests, even on /scans', () => {
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('GET', '/', '/scans'))).toBe(false);
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('GET', '/scans', '/scans'))).toBe(false);
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('DELETE', '/scans/abc', '/scans/abc'))).toBe(false);
  });

  it('does NOT match POST to other routes', () => {
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('POST', '/login', '/login'))).toBe(false);
    expect(AuthAwareThrottlerGuard.isScanCreate(ctxFor('POST', '/scans/:id/stream', '/scans/abc/stream'))).toBe(false);
  });
});
