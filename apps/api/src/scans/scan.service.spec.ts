import {
  BadRequestException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import { Queue } from 'bullmq';

import { ScanQueueProducer, env, type ScanJobPayload } from '@anthrion/shared';

import { BaseChainAdapter } from '../payments/base-chain-adapter';
import { NotConfiguredFacilitatorClient } from '../payments/facilitator-client';
import { ACTIVE_CHAIN_ADAPTER } from '../payments/payment.constants';
import { PaymentService } from '../payments/payment.service';
import { ScanPricing } from '../payments/pricing';
import { PrismaService } from '../prisma/prisma.service';

import { PaymentGate } from './payment-gate';
import { PaymentRequiredException } from './payment-required.exception';
import { SCAN_QUEUE_PRODUCER } from './scan-queue.providers';
import { ScanService } from './scan.service';

/**
 * ScanService integration tests (T4.1 + T5.2) — REAL Postgres + REAL Redis (no mocks),
 * mirroring the Sprint 3 real-infra pattern. Run `docker compose up -d` first.
 *
 * The producer is bound to a UNIQUE queue name for isolation (no worker runs here, so
 * enqueued jobs simply wait in Redis to be inspected, then are obliterated).
 *
 * The pay gate is REAL (T5.2): the DI-wired `service` uses FREE_PRICING (price 0 — the Phase 1
 * default, the active path), and `buildScanService(price)` builds a service at a chosen price
 * for the priced (402 / malformed / facilitator-boundary) paths, exactly as the PaymentService
 * spec does — no payment-layer mocks.
 */

const connection = { url: env.REDIS_URL };
const queueName = `scan-api-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const TREASURY = '0xTreasury0000000000000000000000000000beef';
const USDC = '0xUSDC00000000000000000000000000000000cafe';

function buildAdapter(): BaseChainAdapter {
  return new BaseChainAdapter({
    network: 'base',
    asset: USDC,
    payTo: TREASURY,
    maxTimeoutSeconds: 60,
    facilitator: new NotConfiguredFacilitatorClient(),
  });
}

/** A well-formed base64 `X-PAYMENT` payload (passes Zod; reaches the facilitator boundary). */
function paymentHeaderFor(nonce: string): string {
  const payload = {
    x402Version: 1,
    scheme: 'exact',
    network: 'base',
    payload: {
      signature: '0xsignature',
      authorization: { from: '0xPayer', to: TREASURY, value: '10000', validAfter: '0', validBefore: '9999999999', nonce },
    },
  };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
}

describe('ScanService (real Postgres + Redis)', () => {
  let moduleRef: TestingModule;
  let service: ScanService;
  let prisma: PrismaService;
  let paymentGate: PaymentGate;
  let producer: ScanQueueProducer;
  let inspectQueue: Queue;

  // Distinct authenticated users (by Privy id) to exercise ownership isolation.
  const privyA = `did:privy:scan-A-${Date.now()}`;
  const privyB = `did:privy:scan-B-${Date.now()}`;
  // A user WITH a linked wallet, for the free-trial vertical slice (T5.3).
  const privyW = `did:privy:scan-W-${Date.now()}`;
  const walletW = `0xWalletScanW-${Date.now()}`;
  let userIdA = '';
  let userIdB = '';
  let userIdW = '';

  /** Build a ScanService at a chosen price, sharing the same Postgres + Redis as the suite. */
  function buildScanService(price: string): ScanService {
    const payments = new PaymentService(prisma, new ScanPricing(price), buildAdapter());
    return new ScanService(prisma, new PaymentGate(payments), producer);
  }

  /** Total jobs sitting in the queue (no worker drains it) — used to assert "no job enqueued". */
  async function waitingJobCount(): Promise<number> {
    const jobs = await inspectQueue.getJobs(['waiting', 'delayed', 'active', 'prioritized']);
    return jobs.length;
  }

  beforeAll(async () => {
    producer = new ScanQueueProducer(connection, queueName);
    inspectQueue = new Queue(queueName, { connection });

    moduleRef = await Test.createTestingModule({
      providers: [
        ScanService,
        PaymentGate,
        PaymentService,
        PrismaService,
        // The DI-wired service uses FREE_PRICING (Phase 1 default, the active path).
        { provide: ScanPricing, useFactory: (): ScanPricing => new ScanPricing('0') },
        { provide: ACTIVE_CHAIN_ADAPTER, useFactory: (): BaseChainAdapter => buildAdapter() },
        { provide: SCAN_QUEUE_PRODUCER, useValue: producer },
      ],
    }).compile();
    await moduleRef.init(); // runs PrismaService.onModuleInit ($connect)

    service = moduleRef.get(ScanService);
    prisma = moduleRef.get(PrismaService);
    paymentGate = moduleRef.get(PaymentGate);

    const a = await prisma.user.create({ data: { privyUserId: privyA } });
    const b = await prisma.user.create({ data: { privyUserId: privyB } });
    const w = await prisma.user.create({
      data: { privyUserId: privyW, wallets: { create: { address: walletW, chain: 'EVM' } } },
    });
    userIdA = a.id;
    userIdB = b.id;
    userIdW = w.id;
  });

  afterAll(async () => {
    const ids = [userIdA, userIdB, userIdW];
    // Payment → Scan cascades on scan delete, but clear explicitly for clarity.
    await prisma.payment.deleteMany({ where: { userId: { in: ids } } });
    await prisma.scan.deleteMany({ where: { userId: { in: ids } } });
    await prisma.wallet.deleteMany({ where: { userId: { in: ids } } });
    await prisma.user.deleteMany({ where: { id: { in: ids } } });
    await inspectQueue.obliterate({ force: true });
    await inspectQueue.close();
    await producer.close();
    await moduleRef.close(); // runs PrismaService.onModuleDestroy ($disconnect)
  });

  async function jobFor(scanId: string): Promise<ScanJobPayload | undefined> {
    const jobs = await inspectQueue.getJobs(['waiting', 'delayed', 'active', 'prioritized']);
    return jobs.find((job) => job.data.scanId === scanId)?.data;
  }

  // ── POST /scans: create + enqueue (both scan types) ─────────────────────────

  it('creates a QUEUED web scan record and enqueues a matching job', async () => {
    const res = await service.createScan(privyA, {
      scanType: 'web-app-vuln',
      target: { url: 'https://victim.example/app' },
    });
    expect(res.status).toBe('QUEUED');
    expect(res.scanType).toBe('web-app-vuln');

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: res.scanId } });
    expect(scan.status).toBe('QUEUED');
    expect(scan.scanType).toBe('WEB_APP_VULN');
    expect(scan.targetUrl).toBe('https://victim.example/app');
    expect(scan.targetKind).toBeNull();
    expect(scan.userId).toBe(userIdA);

    const job = await jobFor(res.scanId);
    expect(job).toBeDefined();
    expect(job).toMatchObject({
      scanId: res.scanId,
      scanType: 'web-app-vuln',
      target: { url: 'https://victim.example/app' },
    });
  });

  it('creates an AI endpoint scan; auth rides the job but is NEVER persisted in Postgres', async () => {
    const res = await service.createScan(privyA, {
      scanType: 'ai-llm-attack',
      target: {
        kind: 'endpoint',
        url: 'https://agent.example/chat',
        auth: { type: 'bearer', value: 'super-secret-token' },
      },
    });

    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: res.scanId } });
    expect(scan.scanType).toBe('AI_LLM_ATTACK');
    expect(scan.targetKind).toBe('endpoint');
    expect(scan.targetUrl).toBe('https://agent.example/chat');
    // No column stores auth — assert no serialized field leaks the secret (CLAUDE.md §7).
    expect(JSON.stringify(scan)).not.toContain('super-secret-token');

    // The worker still receives the auth via the queue payload.
    const job = await jobFor(res.scanId);
    expect(job).toMatchObject({
      scanType: 'ai-llm-attack',
      target: { kind: 'endpoint', auth: { type: 'bearer', value: 'super-secret-token' } },
    });
  });

  it('creates an AI system-prompt scan (targetUrl null, targetKind system-prompt)', async () => {
    const res = await service.createScan(privyA, {
      scanType: 'ai-llm-attack',
      target: { kind: 'system-prompt', prompt: 'You are a helpful banking assistant.' },
    });
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: res.scanId } });
    expect(scan.targetUrl).toBeNull();
    expect(scan.targetKind).toBe('system-prompt');

    const job = await jobFor(res.scanId);
    expect(job).toMatchObject({ scanType: 'ai-llm-attack', target: { kind: 'system-prompt' } });
  });

  // ── Validation (Zod → 400) ──────────────────────────────────────────────────

  it('rejects an invalid body with BadRequest (400) and enqueues nothing', async () => {
    await expect(
      service.createScan(privyA, { scanType: 'web-app-vuln', target: { url: 'not-a-url' } }),
    ).rejects.toBeInstanceOf(BadRequestException);

    await expect(service.createScan(privyA, { scanType: 'nope' })).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  // ── Pay gate is real (T5.2) ──────────────────────────────────────────────────

  it('runs the pay gate and records a FREE_PRICING payment before enqueueing (price 0, active path)', async () => {
    const spy = jest.spyOn(paymentGate, 'authorizeScan');
    try {
      const res = await service.createScan(privyA, {
        scanType: 'web-app-vuln',
        target: { url: 'https://gate.example/' },
      });
      // The gate is called with the created scan id as the x402 `resource`, BEFORE enqueue.
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({ userId: userIdA, scanType: 'web-app-vuln', resource: `/scans/${res.scanId}` }),
      );
      expect(res.status).toBe('QUEUED');

      // FREE_PRICING payment recorded & linked (Payment↔Scan consistency on the success path).
      const payment = await prisma.payment.findUnique({ where: { scanId: res.scanId } });
      expect(payment?.kind).toBe('FREE_PRICING');
      expect(payment?.status).toBe('SETTLED');
      expect(payment?.userId).toBe(userIdA);

      // Job enqueued (the scan can run).
      expect(await jobFor(res.scanId)).toBeDefined();
    } finally {
      spy.mockRestore();
    }
  });

  it('priced scan with no X-PAYMENT → 402 with PaymentRequirements; no scan, no payment, no job (real control point)', async () => {
    const paid = buildScanService('10000');
    const scansBefore = await prisma.scan.count({ where: { userId: userIdB } });
    const jobsBefore = await waitingJobCount();

    const error = await paid
      .createScan(privyB, { scanType: 'web-app-vuln', target: { url: 'https://pay.example/' } })
      .then(() => null)
      .catch((e: unknown) => e);

    // 402 is a NORMAL, structured response (not an error path) — assert its shape.
    expect(error).toBeInstanceOf(PaymentRequiredException);
    if (error instanceof PaymentRequiredException) {
      expect(error.getStatus()).toBe(402);
      const body = error.getResponse();
      // The body carries the x402 requirements the caller pays, then retries with X-PAYMENT.
      expect(body).toMatchObject({
        x402Version: 1,
        accepts: [
          expect.objectContaining({
            scheme: 'exact',
            network: 'base',
            maxAmountRequired: '10000',
            payTo: TREASURY,
            asset: USDC,
            resource: expect.stringMatching(/^\/scans\//),
          }),
        ],
      });
    }

    // No pay → no scan, no payment, no job.
    expect(await prisma.scan.count({ where: { userId: userIdB } })).toBe(scansBefore);
    expect(await prisma.payment.count({ where: { userId: userIdB } })).toBe(0);
    expect(await waitingJobCount()).toBe(jobsBefore);
  });

  it('priced scan with a malformed X-PAYMENT → 400 (clear rejection); no scan, no job', async () => {
    const paid = buildScanService('10000');
    const scansBefore = await prisma.scan.count({ where: { userId: userIdB } });
    const jobsBefore = await waitingJobCount();

    await expect(
      paid.createScan(
        privyB,
        { scanType: 'web-app-vuln', target: { url: 'https://broken-pay.example/' } },
        'not-a-valid-x-payment-header',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(await prisma.scan.count({ where: { userId: userIdB } })).toBe(scansBefore);
    expect(await waitingJobCount()).toBe(jobsBefore);
  });

  it('priced scan with a valid X-PAYMENT reaches the facilitator boundary → 503; no scan, no job', async () => {
    const paid = buildScanService('10000');
    const scansBefore = await prisma.scan.count({ where: { userId: userIdB } });
    const jobsBefore = await waitingJobCount();

    // A valid payload passes Zod, then verify/settle hit NotConfiguredFacilitatorClient — the
    // marked T5.1 boundary. The real on-chain settle path waits for the final facilitator.
    await expect(
      paid.createScan(
        privyB,
        { scanType: 'ai-llm-attack', target: { kind: 'system-prompt', prompt: 'You are a bot.' } },
        paymentHeaderFor('0xscan-gate-nonce'),
      ),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(await prisma.scan.count({ where: { userId: userIdB } })).toBe(scansBefore);
    expect(await waitingJobCount()).toBe(jobsBefore);
  });

  // ── Free trial per wallet (T5.3), end-to-end through the scan flow ───────────

  it('free trial: a wallet’s first priced scan → FREE_TRIAL + QUEUED + job (201); after DONE the next is paid (402)', async () => {
    const paid = buildScanService('10000');

    // 1) First priced scan for a wallet-linked account → free trial (no 402).
    const first = await paid.createScan(privyW, { scanType: 'web-app-vuln', target: { url: 'https://ft.example/' } });
    expect(first.status).toBe('QUEUED');
    const payment = await prisma.payment.findUnique({ where: { scanId: first.scanId } });
    expect(payment?.kind).toBe('FREE_TRIAL');
    expect(payment?.walletAddress).toBe(walletW);
    expect(await jobFor(first.scanId)).toBeDefined();

    // 2) The trial counts only once the scan is DONE — simulate the worker finishing it.
    await prisma.scan.update({ where: { id: first.scanId }, data: { status: 'DONE', finishedAt: new Date() } });

    // 3) Next scan for the same wallet is no longer free → paid path (402), no scan/job left.
    const scansBefore = await prisma.scan.count({ where: { userId: userIdW } });
    const jobsBefore = await waitingJobCount();
    await expect(
      paid.createScan(privyW, { scanType: 'web-app-vuln', target: { url: 'https://ft2.example/' } }),
    ).rejects.toBeInstanceOf(PaymentRequiredException);
    expect(await prisma.scan.count({ where: { userId: userIdW } })).toBe(scansBefore);
    expect(await waitingJobCount()).toBe(jobsBefore);
  });

  // ── Scan detail carries payment kind + status (T5.4 Part 1) ─────────────────

  it('getScanById exposes the payment kind + status, and never the raw on-chain payload', async () => {
    const { scanId } = await service.createScan(privyA, {
      scanType: 'web-app-vuln',
      target: { url: 'https://paid-info.example/' },
    });

    const detail = await service.getScanById(privyA, scanId);
    // Real data from the linked Payment record (FREE_PRICING in Phase 1, price 0).
    expect(detail.payment).toEqual({ kind: 'FREE_PRICING', status: 'SETTLED' });

    // Only kind + status cross the wire — no on-chain proof columns leak (CLAUDE.md §7).
    const serialized = JSON.stringify(detail);
    expect(serialized).not.toContain('rawPayload');
    expect(serialized).not.toContain('settleTxHash');
    expect(serialized).not.toContain('nonce');
  });

  // ── Authorization: a user only sees their own scans ─────────────────────────

  it('getScanById returns the owner their scan, and 404s for another user', async () => {
    const { scanId } = await service.createScan(privyA, {
      scanType: 'web-app-vuln',
      target: { url: 'https://owned.example/' },
    });

    const owned = await service.getScanById(privyA, scanId);
    expect(owned.id).toBe(scanId);

    // User B must not see user A's scan — 404 (no existence leak), not the record.
    await expect(service.getScanById(privyB, scanId)).rejects.toBeInstanceOf(NotFoundException);
  });

  it('getScanById 404s for a non-existent scan', async () => {
    await expect(service.getScanById(privyA, 'does-not-exist')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  // ── Report download authorization (T6.1) ─────────────────────────────────────

  it('getReportArtifactForOwner returns the report to the owner, 404s for another user', async () => {
    const { scanId } = await service.createScan(privyA, {
      scanType: 'web-app-vuln',
      target: { url: 'https://report-owned.example/' },
    });
    // Simulate the worker having stored a report PDF artifact for this scan.
    await prisma.artifact.create({
      data: {
        scanId,
        type: 'REPORT_PDF',
        bucket: 'anthrion',
        objectKey: `scans/${scanId}/report.pdf`,
        contentType: 'application/pdf',
        sizeBytes: 1234,
      },
    });

    const ref = await service.getReportArtifactForOwner(privyA, scanId);
    expect(ref.objectKey).toBe(`scans/${scanId}/report.pdf`);
    expect(ref.contentType).toBe('application/pdf');

    // A non-owner gets 404 (no existence leak) — never another user's report.
    await expect(service.getReportArtifactForOwner(privyB, scanId)).rejects.toBeInstanceOf(NotFoundException);

    // reportAvailable is reflected on the detail for the owner.
    const detail = await service.getScanById(privyA, scanId);
    expect(detail.reportAvailable).toBe(true);
  });

  it('getReportArtifactForOwner 404s when the scan has no report artifact', async () => {
    const { scanId } = await service.createScan(privyA, {
      scanType: 'web-app-vuln',
      target: { url: 'https://no-report.example/' },
    });
    await expect(service.getReportArtifactForOwner(privyA, scanId)).rejects.toBeInstanceOf(NotFoundException);
    const detail = await service.getScanById(privyA, scanId);
    expect(detail.reportAvailable).toBe(false);
    // T6.2: a scan whose report never generated has no coverage value → render as neutral.
    expect(detail.reportCoverage).toBeNull();
  });

  it('getScanById surfaces the persisted reportCoverage so UI and PDF share one truth (T6.2)', async () => {
    const { scanId } = await service.createScan(privyA, {
      scanType: 'web-app-vuln',
      target: { url: 'https://coverage.example/' },
    });
    // Simulate the worker having written the same coverage value it put in the PDF.
    const coverage = {
      complete: false,
      gaps: [
        {
          kind: 'web-probes-not-executed',
          title: 'Some probes did not execute',
          detail: '2 of 8 probe(s) did not execute (timeout or error).',
        },
      ],
    };
    await prisma.scan.update({
      where: { id: scanId },
      data: { reportCoverage: coverage },
    });

    const detail = await service.getScanById(privyA, scanId);
    expect(detail.reportCoverage).toEqual(coverage);
  });

  it('listScans returns only the calling user’s scans', async () => {
    // userB created nothing successful so far (the 402 / malformed / boundary attempts all
    // discarded their scan, so no record survives).
    const listB = await service.listScans(privyB);
    expect(listB.scans).toHaveLength(0);

    const listA = await service.listScans(privyA);
    expect(listA.scans.length).toBeGreaterThan(0);
    // Every returned scan belongs to A (verified via DB ownership).
    for (const summary of listA.scans) {
      const scan = await prisma.scan.findUniqueOrThrow({ where: { id: summary.id } });
      expect(scan.userId).toBe(userIdA);
    }
  });

  // ── Enqueue failure after the record + payment are created (Part A) ──────────

  it('marks the scan FAILED if enqueue fails after the record is created, keeping the payment consistent', async () => {
    const spy = jest
      .spyOn(producer, 'enqueueScan')
      .mockRejectedValueOnce(new Error('redis exploded'));
    try {
      await expect(
        service.createScan(privyB, { scanType: 'web-app-vuln', target: { url: 'https://flaky.example/' } }),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      // The record must not silently linger as QUEUED with no job behind it.
      const failed = await prisma.scan.findFirst({
        where: { userId: userIdB, status: 'FAILED' },
        orderBy: { createdAt: 'desc' },
      });
      if (failed === null) {
        throw new Error('expected a FAILED scan record for userB');
      }
      expect(failed.failureReason).toMatch(/enqueue-failed: redis exploded/);
      expect(failed.finishedAt).not.toBeNull();

      // Payment↔Scan consistency on partial failure: the FREE_PRICING payment stays linked to
      // the FAILED scan (FREE_* charged nothing → refund is a no-op, nothing to reverse).
      const payment = await prisma.payment.findUnique({ where: { scanId: failed.id } });
      expect(payment?.kind).toBe('FREE_PRICING');
      expect(payment?.status).toBe('SETTLED');
    } finally {
      spy.mockRestore();
    }
  });
});
