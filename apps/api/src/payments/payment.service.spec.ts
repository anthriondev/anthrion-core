import { Test, type TestingModule } from '@nestjs/testing';

import type { Payment } from '@anthrion/db';

import { PrismaService } from '../prisma/prisma.service';

import { BaseChainAdapter } from './base-chain-adapter';
import { NotConfiguredFacilitatorClient } from './facilitator-client';
import { PaymentInvalidError, PaymentNotConfiguredError } from './payment.errors';
import { PaymentService } from './payment.service';
import { ScanPricing } from './pricing';

/**
 * PaymentService integration tests (T5.1) — REAL Postgres (no mocks), mirroring the Sprint 3
 * pattern. Run `docker compose up -d` first.
 *
 * The FREE_PRICING path runs fully end-to-end. The PAID path is structured but hits the
 * placeholder facilitator / adapter, which reject with PaymentNotConfiguredError — the
 * explicit T5.1 boundary, asserted here.
 */

const TREASURY = '0xTreasury0000000000000000000000000000beef';
const USDC = '0xUSDC00000000000000000000000000000000cafe';

function baseAdapter(): BaseChainAdapter {
  return new BaseChainAdapter({
    network: 'base',
    asset: USDC,
    payTo: TREASURY,
    maxTimeoutSeconds: 60,
    facilitator: new NotConfiguredFacilitatorClient(),
  });
}

function freeService(prisma: PrismaService): PaymentService {
  return new PaymentService(prisma, new ScanPricing('0'), baseAdapter());
}

function paidService(prisma: PrismaService): PaymentService {
  return new PaymentService(prisma, new ScanPricing('10000'), baseAdapter());
}

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

describe('PaymentService (real Postgres)', () => {
  let moduleRef: TestingModule;
  let prisma: PrismaService;
  let userId = '';
  const privyId = `did:privy:pay-${Date.now()}`;
  // Extra accounts (some with wallets) created by the free-trial tests — cleaned in afterAll.
  const extraUserIds: string[] = [];

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({ providers: [PrismaService] }).compile();
    await moduleRef.init();
    prisma = moduleRef.get(PrismaService);
    const user = await prisma.user.create({ data: { privyUserId: privyId } });
    userId = user.id;
  });

  afterAll(async () => {
    const ids = [userId, ...extraUserIds];
    await prisma.payment.deleteMany({ where: { userId: { in: ids } } });
    await prisma.scan.deleteMany({ where: { userId: { in: ids } } });
    await prisma.wallet.deleteMany({ where: { userId: { in: ids } } });
    await prisma.user.deleteMany({ where: { id: { in: ids } } });
    await moduleRef.close();
  });

  async function newScanId(): Promise<string> {
    const scan = await prisma.scan.create({ data: { scanType: 'AI_LLM_ATTACK', userId } });
    return scan.id;
  }

  /** A fresh account with one linked EVM wallet (the free trial binds to a wallet). */
  async function newAccountWithWallet(address: string): Promise<string> {
    const user = await prisma.user.create({
      data: {
        privyUserId: `did:privy:ft-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        wallets: { create: { address, chain: 'EVM' } },
      },
    });
    extraUserIds.push(user.id);
    return user.id;
  }

  /** Unique wallet address per call (Wallet.address is globally unique). */
  function freshAddress(tag: string): string {
    return `0xWalletFT-${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }

  async function newScanIdForUser(uid: string): Promise<string> {
    const scan = await prisma.scan.create({ data: { scanType: 'AI_LLM_ATTACK', userId: uid } });
    return scan.id;
  }

  // ── Pricing ─────────────────────────────────────────────────────────────────

  it('ScanPricing reports free for 0 and paid for >0', () => {
    expect(new ScanPricing('0').priceForScan('ai-llm-attack').isFree).toBe(true);
    const paid = new ScanPricing('10000').priceForScan('ai-llm-attack');
    expect(paid.isFree).toBe(false);
    expect(paid.atomicUnits).toBe(10000n);
  });

  // ── FREE_PRICING — full end-to-end ──────────────────────────────────────────

  it('price 0 records a FREE_PRICING payment with no on-chain fields and allows the scan', async () => {
    const scanId = await newScanId();
    const outcome = await freeService(prisma).authorizeScan({
      scanId,
      userId,
      scanType: 'ai-llm-attack',
      resource: `/scans/${scanId}`,
    });

    expect(outcome.kind).toBe('free-pricing');

    const row = await prisma.payment.findUnique({ where: { scanId } });
    expect(row).not.toBeNull();
    expect(row?.kind).toBe('FREE_PRICING');
    expect(row?.status).toBe('SETTLED');
    expect(row?.network).toBeNull();
    expect(row?.asset).toBeNull();
    expect(row?.amountAtomic).toBeNull();
    expect(row?.settleTxHash).toBeNull();
    expect(row?.walletAddress).toBeNull();
  });

  // ── Double-spend guards (uniqueness) ────────────────────────────────────────

  it('rejects a second payment for the same scanId (one payment per scan)', async () => {
    const scanId = await newScanId();
    await prisma.payment.create({ data: { scanId, userId, kind: 'FREE_PRICING', status: 'SETTLED' } });
    await expect(prisma.payment.create({ data: { scanId, userId, kind: 'FREE_PRICING', status: 'SETTLED' } })).rejects.toThrow();
  });

  it('rejects a duplicate (network, nonce) authorization', async () => {
    const a = await newScanId();
    const b = await newScanId();
    await prisma.payment.create({ data: { scanId: a, userId, kind: 'PAID', status: 'SETTLED', network: 'base', nonce: '0xdupnonce' } });
    await expect(
      prisma.payment.create({ data: { scanId: b, userId, kind: 'PAID', status: 'SETTLED', network: 'base', nonce: '0xdupnonce' } }),
    ).rejects.toThrow();
  });

  it('rejects a duplicate settleTxHash', async () => {
    const a = await newScanId();
    const b = await newScanId();
    await prisma.payment.create({ data: { scanId: a, userId, kind: 'PAID', status: 'SETTLED', settleTxHash: '0xduptx' } });
    await expect(
      prisma.payment.create({ data: { scanId: b, userId, kind: 'PAID', status: 'SETTLED', settleTxHash: '0xduptx' } }),
    ).rejects.toThrow();
  });

  // ── PAID path — structured; facilitator is the marked boundary ──────────────

  it('paid scan with no payment returns payment-required with x402 requirements', async () => {
    const scanId = await newScanId();
    const outcome = await paidService(prisma).authorizeScan({
      scanId,
      userId,
      scanType: 'ai-llm-attack',
      resource: `/scans/${scanId}`,
    });
    expect(outcome.kind).toBe('payment-required');
    if (outcome.kind === 'payment-required') {
      expect(outcome.requirements.scheme).toBe('exact');
      expect(outcome.requirements.network).toBe('base');
      expect(outcome.requirements.maxAmountRequired).toBe('10000');
      expect(outcome.requirements.payTo).toBe(TREASURY);
      expect(outcome.requirements.asset).toBe(USDC);
    }
    // no payment row created on the payment-required branch
    expect(await prisma.payment.findUnique({ where: { scanId } })).toBeNull();
  });

  it('paid scan with a malformed payment payload is rejected (PaymentInvalidError)', async () => {
    const scanId = await newScanId();
    await expect(
      paidService(prisma).authorizeScan({
        scanId,
        userId,
        scanType: 'ai-llm-attack',
        resource: `/scans/${scanId}`,
        paymentHeader: 'not-a-valid-header',
      }),
    ).rejects.toBeInstanceOf(PaymentInvalidError);
  });

  it('paid scan with a valid payment reaches the facilitator boundary (PaymentNotConfiguredError)', async () => {
    const scanId = await newScanId();
    await expect(
      paidService(prisma).authorizeScan({
        scanId,
        userId,
        scanType: 'ai-llm-attack',
        resource: `/scans/${scanId}`,
        paymentHeader: paymentHeaderFor('0xnonce-valid'),
      }),
    ).rejects.toBeInstanceOf(PaymentNotConfiguredError);
    // settlement never happened → no payment row persisted
    expect(await prisma.payment.findUnique({ where: { scanId } })).toBeNull();
  });

  // ── Free trial per wallet (T5.3) — price > 0 so the trial path is reached ────

  it('a new wallet gets a free trial: FREE_TRIAL payment, walletAddress set, on-chain fields null', async () => {
    const address = freshAddress('new');
    const uid = await newAccountWithWallet(address);
    const scanId = await newScanIdForUser(uid);

    const outcome = await paidService(prisma).authorizeScan({
      scanId,
      userId: uid,
      scanType: 'ai-llm-attack',
      resource: `/scans/${scanId}`,
    });

    expect(outcome.kind).toBe('free-trial');
    const row = await prisma.payment.findUnique({ where: { scanId } });
    expect(row?.kind).toBe('FREE_TRIAL');
    expect(row?.status).toBe('SETTLED');
    expect(row?.walletAddress).toBe(address);
    expect(row?.network).toBeNull();
    expect(row?.asset).toBeNull();
    expect(row?.amountAtomic).toBeNull();
    expect(row?.settleTxHash).toBeNull();
  });

  it('a second scan after the wallet’s free-trial scan is DONE is not free → payment-required (DoD)', async () => {
    const address = freshAddress('done');
    const uid = await newAccountWithWallet(address);

    // First scan → free trial; then the worker finishes it (DONE) → the trial is now used.
    const first = await newScanIdForUser(uid);
    expect((await paidService(prisma).authorizeScan({ scanId: first, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${first}` })).kind).toBe('free-trial');
    await prisma.scan.update({ where: { id: first }, data: { status: 'DONE', finishedAt: new Date() } });

    // Second scan, same wallet → no free trial left → paid path.
    const second = await newScanIdForUser(uid);
    const outcome = await paidService(prisma).authorizeScan({ scanId: second, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${second}` });
    expect(outcome.kind).toBe('payment-required');
    expect(await prisma.payment.findUnique({ where: { scanId: second } })).toBeNull();
  });

  it('a free-trial scan that FAILED does not consume the trial → wallet stays eligible (no "give back" step)', async () => {
    const address = freshAddress('failed');
    const uid = await newAccountWithWallet(address);

    const first = await newScanIdForUser(uid);
    expect((await paidService(prisma).authorizeScan({ scanId: first, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${first}` })).kind).toBe('free-trial');
    // The free-trial scan fails — the FREE_TRIAL payment row stays as a record...
    await prisma.scan.update({ where: { id: first }, data: { status: 'FAILED', failureReason: 'sandbox-error', finishedAt: new Date() } });
    expect(await prisma.payment.findUnique({ where: { scanId: first } })).not.toBeNull();

    // ...but since the scan is not DONE, the wallet is still eligible for a free trial.
    const second = await newScanIdForUser(uid);
    const outcome = await paidService(prisma).authorizeScan({ scanId: second, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${second}` });
    expect(outcome.kind).toBe('free-trial');
  });

  it('a non-terminal (QUEUED) free trial closes eligibility for the next trial (no parallel trials)', async () => {
    const address = freshAddress('inflight');
    const uid = await newAccountWithWallet(address);

    // First free trial; its scan stays QUEUED (not finished).
    const first = await newScanIdForUser(uid);
    expect((await paidService(prisma).authorizeScan({ scanId: first, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${first}` })).kind).toBe('free-trial');

    // A second attempt while the first is still in flight → not free.
    const second = await newScanIdForUser(uid);
    const outcome = await paidService(prisma).authorizeScan({ scanId: second, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${second}` });
    expect(outcome.kind).toBe('payment-required');
  });

  it('one wallet using its trial does not affect a different wallet', async () => {
    const addrA = freshAddress('indepA');
    const addrB = freshAddress('indepB');
    const uidA = await newAccountWithWallet(addrA);
    const uidB = await newAccountWithWallet(addrB);

    // Wallet A uses and completes its trial.
    const aScan = await newScanIdForUser(uidA);
    expect((await paidService(prisma).authorizeScan({ scanId: aScan, userId: uidA, scanType: 'ai-llm-attack', resource: `/scans/${aScan}` })).kind).toBe('free-trial');
    await prisma.scan.update({ where: { id: aScan }, data: { status: 'DONE', finishedAt: new Date() } });

    // Wallet B is untouched → still gets its own free trial.
    const bScan = await newScanIdForUser(uidB);
    expect((await paidService(prisma).authorizeScan({ scanId: bScan, userId: uidB, scanType: 'ai-llm-attack', resource: `/scans/${bScan}` })).kind).toBe('free-trial');
  });

  it('with price 0 a wallet scan is FREE_PRICING, not FREE_TRIAL (the free trial sleeps)', async () => {
    const address = freshAddress('zero');
    const uid = await newAccountWithWallet(address);
    const scanId = await newScanIdForUser(uid);

    const outcome = await freeService(prisma).authorizeScan({ scanId, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${scanId}` });
    expect(outcome.kind).toBe('free-pricing');
    const row = await prisma.payment.findUnique({ where: { scanId } });
    expect(row?.kind).toBe('FREE_PRICING'); // the wallet's free trial is untouched
  });

  it('an account with no linked wallet is not trial-eligible → payment-required (trial binds to a wallet)', async () => {
    const noWallet = await prisma.user.create({ data: { privyUserId: `did:privy:ft-nowallet-${Date.now()}` } });
    extraUserIds.push(noWallet.id);
    const scanId = await newScanIdForUser(noWallet.id);

    const outcome = await paidService(prisma).authorizeScan({ scanId, userId: noWallet.id, scanType: 'ai-llm-attack', resource: `/scans/${scanId}` });
    expect(outcome.kind).toBe('payment-required');
    expect(await prisma.payment.findUnique({ where: { scanId } })).toBeNull();
  });

  it('concurrent free-trial attempts for the same wallet grant exactly one trial (anti-race)', async () => {
    const address = freshAddress('race');
    const uid = await newAccountWithWallet(address);
    const s1 = await newScanIdForUser(uid);
    const s2 = await newScanIdForUser(uid);
    const svc = paidService(prisma);

    const [o1, o2] = await Promise.all([
      svc.authorizeScan({ scanId: s1, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${s1}` }),
      svc.authorizeScan({ scanId: s2, userId: uid, scanType: 'ai-llm-attack', resource: `/scans/${s2}` }),
    ]);

    // Exactly one wins the trial; the other is pushed to the paid path.
    expect([o1.kind, o2.kind].sort()).toEqual(['free-trial', 'payment-required']);
    expect(await prisma.payment.count({ where: { walletAddress: address, kind: 'FREE_TRIAL' } })).toBe(1);
  });

  // ── Free-trial status (read-only, T5.4 Part 2) ──────────────────────────────

  /** Fresh account with one linked EVM wallet; returns the ids needed to read trial status. */
  async function newAccountForStatus(): Promise<{ privyUserId: string; userId: string; address: string }> {
    const privyUserId = `did:privy:fts-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const address = freshAddress('status');
    const user = await prisma.user.create({
      data: { privyUserId, wallets: { create: { address, chain: 'EVM' } } },
    });
    extraUserIds.push(user.id);
    return { privyUserId, userId: user.id, address };
  }

  it('getFreeTrialStatus: a wallet with an unused trial reads "available" (with its wallet)', async () => {
    const { privyUserId, address } = await newAccountForStatus();
    const status = await paidService(prisma).getFreeTrialStatus(privyUserId);
    expect(status.status).toBe('available');
    expect(status.walletAddress).toBe(address);
  });

  it('getFreeTrialStatus: "available" even with price 0 — the trial sleeps but is untouched', async () => {
    const { privyUserId } = await newAccountForStatus();
    // Read via the free-priced service: pricing must NOT change the eligibility answer.
    const status = await freeService(prisma).getFreeTrialStatus(privyUserId);
    expect(status.status).toBe('available');
  });

  it('getFreeTrialStatus: reads "used" after the wallet’s trial scan is DONE', async () => {
    const { privyUserId, userId } = await newAccountForStatus();
    const scanId = await newScanIdForUser(userId);
    expect((await paidService(prisma).authorizeScan({ scanId, userId, scanType: 'ai-llm-attack', resource: `/scans/${scanId}` })).kind).toBe('free-trial');
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'DONE', finishedAt: new Date() } });

    expect((await paidService(prisma).getFreeTrialStatus(privyUserId)).status).toBe('used');
  });

  it('getFreeTrialStatus: an in-flight (QUEUED) trial also reads "used" (no parallel trials)', async () => {
    const { privyUserId, userId } = await newAccountForStatus();
    const scanId = await newScanIdForUser(userId);
    expect((await paidService(prisma).authorizeScan({ scanId, userId, scanType: 'ai-llm-attack', resource: `/scans/${scanId}` })).kind).toBe('free-trial');
    // scan stays QUEUED (not finished)
    expect((await paidService(prisma).getFreeTrialStatus(privyUserId)).status).toBe('used');
  });

  it('getFreeTrialStatus: a FAILED trial scan leaves the wallet "available" (no give-back step)', async () => {
    const { privyUserId, userId } = await newAccountForStatus();
    const scanId = await newScanIdForUser(userId);
    expect((await paidService(prisma).authorizeScan({ scanId, userId, scanType: 'ai-llm-attack', resource: `/scans/${scanId}` })).kind).toBe('free-trial');
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED', failureReason: 'x', finishedAt: new Date() } });

    expect((await paidService(prisma).getFreeTrialStatus(privyUserId)).status).toBe('available');
  });

  it('getFreeTrialStatus: an account with no wallet reads "no-wallet" (trial binds to a wallet)', async () => {
    const noWallet = await prisma.user.create({ data: { privyUserId: `did:privy:fts-nowallet-${Date.now()}` } });
    extraUserIds.push(noWallet.id);
    const status = await paidService(prisma).getFreeTrialStatus(noWallet.privyUserId);
    expect(status.status).toBe('no-wallet');
    expect(status.walletAddress).toBeNull();
  });

  it('getFreeTrialStatus: an unknown user is rejected (authorization, not an empty result)', async () => {
    await expect(paidService(prisma).getFreeTrialStatus('did:privy:does-not-exist')).rejects.toThrow();
  });

  // ── Refund — structured; execution is the marked boundary ───────────────────

  it('refund is a no-op for a FREE_PRICING scan (nothing was charged)', async () => {
    const scanId = await newScanId();
    await freeService(prisma).authorizeScan({ scanId, userId, scanType: 'ai-llm-attack', resource: `/scans/${scanId}` });
    await freeService(prisma).refundForFailedScan(scanId); // resolves, no throw
    const row = await prisma.payment.findUnique({ where: { scanId } });
    expect(row?.status).toBe('SETTLED');
  });

  it('refund of a settled PAID scan marks REFUND_PENDING then hits the execution boundary', async () => {
    const scanId = await newScanId();
    const settled: Payment = await prisma.payment.create({
      data: {
        scanId,
        userId,
        kind: 'PAID',
        status: 'SETTLED',
        walletAddress: '0xPayer',
        network: 'base',
        asset: USDC,
        amountAtomic: '10000',
        payTo: TREASURY,
        nonce: '0xrefund-nonce',
        settleTxHash: '0xrefund-tx',
      },
    });
    expect(settled.status).toBe('SETTLED');

    await expect(paidService(prisma).refundForFailedScan(scanId)).rejects.toBeInstanceOf(PaymentNotConfiguredError);

    // status advanced to REFUND_PENDING before the (unimplemented) execution
    const row = await prisma.payment.findUnique({ where: { scanId } });
    expect(row?.status).toBe('REFUND_PENDING');
  });
});
