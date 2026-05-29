import { INestApplication } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import IORedis from 'ioredis';
import request from 'supertest';

import { createPrismaClient, type PrismaClient } from '@anthrion/db';
import { env, scanProgressChannel } from '@anthrion/shared';

import { AuthService } from '../auth/auth.service';
import { BaseChainAdapter } from '../payments/base-chain-adapter';
import { NotConfiguredFacilitatorClient } from '../payments/facilitator-client';
import { ACTIVE_CHAIN_ADAPTER } from '../payments/payment.constants';
import { PaymentService } from '../payments/payment.service';
import { ScanPricing } from '../payments/pricing';
import { PrismaService } from '../prisma/prisma.service';

import { ArtifactStorageService } from './artifact-storage.service';
import { PaymentGate } from './payment-gate';
import { ScanOwnerGuard } from './scan-owner.guard';
import { ScanStreamService } from './scan-stream.service';
import { SCAN_QUEUE_PRODUCER } from './scan-queue.providers';
import { ScansController } from './scan.controller';
import { ScanService } from './scan.service';

/**
 * SSE streaming tests (T4.2, Part D) — REAL Postgres + REAL Redis.
 *
 * The HTTP happy-path uses supertest, which reads the FULL response body once the stream
 * ends — so the test publishes live events and a terminal DONE, then asserts the body
 * carries the snapshot + live stage + terminal events (proving the api relays the
 * worker's Redis events over SSE). Ownership (404) and auth (401) are exercised over
 * HTTP. Disconnect cleanup is asserted on the relay Observable (subscription teardown).
 */

const claimsFor = (userId: string) => ({
  appId: 'test-app',
  issuer: 'privy.io',
  issuedAt: 1700000000,
  expiration: 9999999999,
  sessionId: 'sess-1',
  userId,
});

const mockAuthService = { verifyToken: jest.fn() };
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe('Scan SSE stream (real Postgres + Redis)', () => {
  let app: INestApplication;
  let prisma: PrismaClient;
  let streamService: ScanStreamService;
  let publisher: IORedis;

  const privyA = `did:privy:sse-A-${Date.now()}`;
  const privyB = `did:privy:sse-B-${Date.now()}`;
  let userIdA = '';
  let userIdB = '';

  beforeAll(async () => {
    publisher = new IORedis(env.REDIS_URL);
    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [ScansController],
      providers: [
        ScanService,
        ScanStreamService,
        ScanOwnerGuard,
        // Wired for DI (the controller injects it for the T6.1 report download); this suite
        // tests the SSE relay and never hits the download route.
        ArtifactStorageService,
        // The pay gate is wired (real, T5.2) but this suite never calls createScan — it tests
        // the SSE relay over scans it inserts directly. FREE_PRICING wiring satisfies DI.
        PaymentGate,
        PaymentService,
        { provide: ScanPricing, useFactory: (): ScanPricing => new ScanPricing('0') },
        {
          provide: ACTIVE_CHAIN_ADAPTER,
          useFactory: (): BaseChainAdapter =>
            new BaseChainAdapter({
              network: 'base',
              asset: '0xUSDC',
              payTo: '0xTreasury',
              maxTimeoutSeconds: 60,
              facilitator: new NotConfiguredFacilitatorClient(),
            }),
        },
        PrismaService,
        { provide: AuthService, useValue: mockAuthService },
        { provide: SCAN_QUEUE_PRODUCER, useValue: { enqueueScan: () => Promise.resolve({}), close: () => Promise.resolve() } },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();

    prisma = moduleRef.get(PrismaService);
    streamService = moduleRef.get(ScanStreamService);

    const a = await prisma.user.create({ data: { privyUserId: privyA } });
    const b = await prisma.user.create({ data: { privyUserId: privyB } });
    userIdA = a.id;
    userIdB = b.id;
  });

  afterEach(() => mockAuthService.verifyToken.mockReset());

  afterAll(async () => {
    await prisma.scan.deleteMany({ where: { userId: { in: [userIdA, userIdB] } } });
    await prisma.user.deleteMany({ where: { id: { in: [userIdA, userIdB] } } });
    await publisher.quit();
    await app.close();
  });

  async function createScan(userId: string, status: 'QUEUED' | 'RUNNING' | 'DONE'): Promise<string> {
    const scan = await prisma.scan.create({
      data: { status, scanType: 'WEB_APP_VULN', targetUrl: 'https://x.example', userId },
    });
    return scan.id;
  }

  // ── Happy path over real SSE (ends on a terminal event) ─────────────────────

  it('streams the snapshot + live stage event + terminal DONE over SSE', async () => {
    mockAuthService.verifyToken.mockResolvedValue(claimsFor(privyA));
    const scanId = await createScan(userIdA, 'RUNNING');

    // Publish live events once the server has connected + subscribed. Redis pub/sub drops
    // messages with no subscriber, so the stage event is published twice (generous delays)
    // to tolerate the per-stream subscribe latency; the terminal DONE ends the stream so
    // supertest resolves with the full body.
    const stage = JSON.stringify({ type: 'stage', phase: 'web-load', status: 'started', message: 'loading' });
    const channel = scanProgressChannel(scanId);
    setTimeout(() => void publisher.publish(channel, stage), 1500);
    setTimeout(() => void publisher.publish(channel, stage), 2500);
    setTimeout(() => void publisher.publish(channel, JSON.stringify({ type: 'lifecycle', status: 'DONE' })), 3500);

    const res = await request(app.getHttpServer())
      .get(`/scans/${scanId}/stream`)
      .set('Authorization', 'Bearer t')
      .expect(200);

    expect(res.headers['content-type']).toMatch(/text\/event-stream/);
    expect(res.text).toContain('"type":"lifecycle"');
    expect(res.text).toContain('"status":"RUNNING"'); // snapshot
    expect(res.text).toContain('"phase":"web-load"'); // live stage event relayed from Redis
    expect(res.text).toContain('"status":"DONE"'); // terminal event completes the stream
  }, 25000);

  // ── Finished-before-connect: snapshot + immediate close (no hang) ───────────

  it('snapshots a finished scan and ends immediately (does not hang)', async () => {
    mockAuthService.verifyToken.mockResolvedValue(claimsFor(privyA));
    const scanId = await createScan(userIdA, 'DONE');

    const res = await request(app.getHttpServer())
      .get(`/scans/${scanId}/stream`)
      .set('Authorization', 'Bearer t')
      .expect(200);

    expect(res.text).toContain('"status":"DONE"');
  }, 20000);

  // ── Authorization ───────────────────────────────────────────────────────────

  it('returns 404 when the scan belongs to another user', async () => {
    mockAuthService.verifyToken.mockResolvedValue(claimsFor(privyB)); // user B
    const scanId = await createScan(userIdA, 'RUNNING'); // owned by A
    await request(app.getHttpServer()).get(`/scans/${scanId}/stream`).set('Authorization', 'Bearer t').expect(404);
  });

  it('returns 401 without a valid token', async () => {
    mockAuthService.verifyToken.mockRejectedValue(new Error('bad'));
    await request(app.getHttpServer()).get('/scans/anything/stream').expect(401);
  });

  // ── Lifecycle: the relay subscription is torn down on disconnect ────────────

  it('tears down the Redis subscription when the client unsubscribes (no leak)', async () => {
    const before = streamService.activeStreams;
    const subscription = streamService.observe('lifecycle-scan', () => Promise.resolve('RUNNING')).subscribe();
    await wait(150); // allow the snapshot + Redis subscribe
    expect(streamService.activeStreams).toBe(before + 1);

    subscription.unsubscribe(); // == client disconnect
    await wait(50);
    expect(streamService.activeStreams).toBe(before);
  });
});
