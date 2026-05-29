import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';

import type { Payment, Prisma } from '@anthrion/db';
import {
  freeTrialStatusResponseSchema,
  type FreeTrialStatusResponse,
  type PaymentPayload,
  type PaymentRequirements,
  type ScanJobType,
} from '@anthrion/shared';

import { PrismaService } from '../prisma/prisma.service';

import type { ChainAdapter } from './chain-adapter';
import { ACTIVE_CHAIN_ADAPTER } from './payment.constants';
import { PaymentInvalidError } from './payment.errors';
import { ScanPricing } from './pricing';

/**
 * Result of authorizing a scan payment. The three "allowed" kinds (`free-pricing`, `free-trial`,
 * `paid`) each carry a recorded `Payment`; `payment-required` means a paid scan arrived without a
 * usable payment — T5.2 turns the `requirements` into an HTTP 402 (the x402-native path, also
 * reused by the Phase 1.5 agent API).
 */
export type PaymentOutcome =
  | { kind: 'free-pricing'; payment: Payment }
  | { kind: 'free-trial'; payment: Payment }
  | { kind: 'paid'; payment: Payment }
  | { kind: 'payment-required'; requirements: PaymentRequirements };

export interface AuthorizeScanInput {
  scanId: string;
  userId: string;
  scanType: ScanJobType;
  /** The resource being paid for, e.g. `/scans/<id>` (x402 `resource`). */
  resource: string;
  description?: string;
  /** The `X-PAYMENT` header value (base64), if the caller attached one. */
  paymentHeader?: string;
}

/**
 * Payment layer service (T5.1, x402-native, billing mechanism A). T5.2 calls `authorizeScan`
 * from the pay gate BEFORE enqueueing a scan; the Phase 1.5 agent API reuses the same path.
 *
 * Resolution order in `authorizeScan`: FREE_PRICING (price 0) → FREE_TRIAL (T5.3, one per wallet)
 * → PAID. With the Phase 1 default price 0, FREE_PRICING captures everything and the free trial
 * "sleeps" — correct, not a bug (a trial is meaningless when every scan is already free); it only
 * comes alive once the price is > 0.
 *
 * Boundary: the FREE_PRICING and FREE_TRIAL paths are fully working end-to-end (no facilitator
 * needed). The PAID path is fully structured but `verify`/`settle` hit the placeholder facilitator
 * (and refund the placeholder adapter), which reject with `PaymentNotConfiguredError` until a
 * facilitator + treasury key store are wired.
 */
@Injectable()
export class PaymentService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly pricing: ScanPricing,
    @Inject(ACTIVE_CHAIN_ADAPTER) private readonly chain: ChainAdapter,
  ) {}

  async authorizeScan(input: AuthorizeScanInput): Promise<PaymentOutcome> {
    const price = this.pricing.priceForScan(input.scanType);

    // FREE_PRICING — global price is 0. Record proof + allow. No on-chain tx, no facilitator.
    if (price.isFree) {
      const payment = await this.prisma.payment.create({
        data: {
          scanId: input.scanId,
          userId: input.userId,
          kind: 'FREE_PRICING',
          status: 'SETTLED',
          settledAt: new Date(),
        },
      });
      return { kind: 'free-pricing', payment };
    }

    // FREE_TRIAL — price > 0, but the scan's wallet may still hold its one-time free trial.
    // Resolution order (T5.1/T5.2): FREE_PRICING (above) → FREE_TRIAL → paid. The trial is bound
    // to the account's primary wallet; an account with no linked wallet is not trial-eligible (the
    // trial binds to a wallet — BUSINESS_MODEL) and falls through to the paid path below.
    const wallet = await this.resolvePrimaryWallet(input.userId);
    if (wallet !== null) {
      const trial = await this.tryConsumeFreeTrial(input, wallet.address);
      if (trial !== null) {
        return trial;
      }
    }

    // PAID — advertise x402 requirements.
    const requirements = this.chain.buildPaymentRequirements({
      amountAtomic: price.atomicUnits,
      resource: input.resource,
      description: input.description ?? 'ANTHRION security scan',
    });

    // No payment attached → T5.2 answers HTTP 402 with these requirements.
    if (input.paymentHeader === undefined || input.paymentHeader === '') {
      return { kind: 'payment-required', requirements };
    }

    // External data → validate before trust (CLAUDE.md §3).
    const payload = this.chain.parsePaymentPayload(input.paymentHeader);
    if (payload === undefined) {
      throw new PaymentInvalidError('Malformed or invalid X-PAYMENT payload');
    }

    const verification = await this.chain.verify(payload, requirements);
    if (!verification.isValid) {
      throw new PaymentInvalidError(verification.invalidReason ?? 'Payment verification failed');
    }

    // Mechanism A: settle BEFORE the scan is enqueued. (Hits the facilitator placeholder in
    // T5.1 — the explicit boundary.)
    const settlement = await this.chain.settle(payload, requirements);
    if (!settlement.success) {
      throw new PaymentInvalidError(settlement.errorReason ?? 'Payment settlement failed');
    }

    const payment = await this.prisma.payment.create({
      data: {
        scanId: input.scanId,
        userId: input.userId,
        kind: 'PAID',
        status: 'SETTLED',
        walletAddress: payload.payload.authorization.from,
        network: payload.network,
        asset: requirements.asset,
        amountAtomic: requirements.maxAmountRequired,
        payTo: requirements.payTo,
        nonce: payload.payload.authorization.nonce,
        scheme: payload.scheme,
        x402Version: payload.x402Version,
        settleTxHash: settlement.txHash ?? null,
        rawPayload: snapshotPayload(payload),
        settledAt: new Date(),
      },
    });
    return { kind: 'paid', payment };
  }

  /**
   * Read-only free-trial availability for a user's primary wallet (T5.4 Part 2, supporting the UI
   * indicator). Mirrors the eligibility rule in {@link tryConsumeFreeTrial} — DERIVED from scan
   * status, never a stored flag — but consumes NOTHING (no advisory lock, no insert): it only
   * reports. Independent of the current price: with FREE_PRICING (price 0) the trial sleeps
   * untouched, so a wallet that has only run promotional free scans still reads `available`.
   *
   * Authorization: takes the authenticated Privy id and resolves the account itself, so a caller
   * can only ever read its own status (the controller passes `req.privyUser.userId`). States:
   *  - no linked wallet → `no-wallet` (the trial binds to a wallet — BUSINESS_MODEL.md).
   *  - a FREE_TRIAL whose scan is DONE / QUEUED / RUNNING → `used` (consumed or in flight).
   *  - otherwise → `available`.
   */
  async getFreeTrialStatus(privyUserId: string): Promise<FreeTrialStatusResponse> {
    const user = await this.prisma.user.findUnique({ where: { privyUserId }, select: { id: true } });
    if (user === null) {
      // The global UserSyncInterceptor creates the row before the handler runs; a miss is an
      // auth failure, not an empty result (mirrors ScanService.resolveUserId).
      throw new UnauthorizedException('Authenticated user not found');
    }

    const wallet = await this.resolvePrimaryWallet(user.id);
    if (wallet === null) {
      return freeTrialStatusResponseSchema.parse({ status: 'no-wallet', walletAddress: null });
    }

    // Same "trial taken" predicate as tryConsumeFreeTrial: non-terminal (QUEUED/RUNNING) or DONE
    // blocks; a FAILED trial does not (it never consumed the trial). Checked GLOBALLY by wallet.
    const blocking = await this.prisma.payment.findFirst({
      where: {
        kind: 'FREE_TRIAL',
        walletAddress: wallet.address,
        scan: { status: { in: ['QUEUED', 'RUNNING', 'DONE'] } },
      },
      select: { id: true },
    });

    return freeTrialStatusResponseSchema.parse({
      status: blocking !== null ? 'used' : 'available',
      walletAddress: wallet.address,
    });
  }

  /**
   * The wallet a free trial binds to (T5.3): the account's PRIMARY wallet — its earliest-linked
   * `Wallet` (createdAt asc, `id` as a stable tie-break). The Privy session identifies the account,
   * not a specific active wallet, so one deterministic wallet is chosen; in Phase 1 (one embedded
   * wallet per account) this is unambiguous. Returns `null` when the account has no linked wallet —
   * such an account is not trial-eligible, since the trial binds to a wallet (BUSINESS_MODEL); it
   * then falls through to the paid path.
   */
  private async resolvePrimaryWallet(userId: string): Promise<{ address: string } | null> {
    return this.prisma.wallet.findFirst({
      where: { userId },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      select: { address: true },
    });
  }

  /**
   * Grant a wallet's one-time free trial if it is still eligible (T5.3). Eligibility is DERIVED
   * from scan status, NOT a stored flag: a wallet is ineligible once it has a FREE_TRIAL payment
   * whose scan is DONE (trial used) OR QUEUED/RUNNING (a trial in flight — this closes the door so
   * parallel trials cannot be started). A FREE_TRIAL whose scan FAILED matches neither, so the
   * wallet stays eligible automatically — there is never an explicit "give the trial back" step
   * (BUSINESS_MODEL: a scan counts only when it finishes DONE). Checked GLOBALLY by wallet address
   * (not scoped to the account) — "one trial per wallet address".
   *
   * Anti-race: the eligibility read + the FREE_TRIAL insert run in ONE transaction guarded by a
   * per-wallet `pg_advisory_xact_lock`. That lock is transaction-scoped (released on commit/
   * rollback), so a concurrent request for the SAME wallet blocks until this one finishes and then
   * observes the just-created (non-terminal) trial → it returns `null` and the caller continues to
   * the paid path. Different wallets hash to different keys and never block each other.
   *
   * Returns the `free-trial` outcome when granted, or `null` when the wallet is not eligible.
   */
  private tryConsumeFreeTrial(input: AuthorizeScanInput, walletAddress: string): Promise<PaymentOutcome | null> {
    return this.prisma.$transaction(async (tx) => {
      // Serialize free-trial authorization per wallet address (anti-race) — see method doc.
      // pg_advisory_xact_lock returns void; wrap it so the query yields a deserializable column.
      await tx.$queryRaw`SELECT 1 AS locked FROM (SELECT pg_advisory_xact_lock(hashtext(${walletAddress}))) AS _lock`;

      // A trial is "taken" while its scan is non-terminal (QUEUED/RUNNING) or DONE; a FAILED
      // trial does not block (so it never consumes the trial). Derived from scan status, no flag.
      const blocking = await tx.payment.findFirst({
        where: {
          kind: 'FREE_TRIAL',
          walletAddress,
          scan: { status: { in: ['QUEUED', 'RUNNING', 'DONE'] } },
        },
        select: { id: true },
      });
      if (blocking !== null) {
        return null; // wallet's trial already used or in flight → caller falls to the paid path
      }

      const payment = await tx.payment.create({
        data: {
          scanId: input.scanId,
          userId: input.userId,
          kind: 'FREE_TRIAL',
          status: 'SETTLED',
          // The wallet the trial is tracked against. On-chain fields stay null (no transaction).
          walletAddress,
          settledAt: new Date(),
        },
      });
      const outcome: PaymentOutcome = { kind: 'free-trial', payment };
      return outcome;
    });
  }

  /**
   * Refund a settled PAID scan that must not bill (FAILED / partial result, per the locked rule).
   * Sets REFUND_PENDING, then executes the refund via the chain adapter — OUR own logic (x402 has
   * no built-in refund). FREE_* scans charged nothing → no-op. Execution is the T5.1 boundary
   * (needs the treasury key); the CALL POINT exists now (the worker/T5.2 invokes it on FAILED).
   */
  async refundForFailedScan(scanId: string): Promise<void> {
    const payment = await this.prisma.payment.findUnique({ where: { scanId } });
    if (payment === null || payment.kind !== 'PAID' || payment.status !== 'SETTLED') {
      return; // nothing charged, or not in a refundable state
    }
    if (
      payment.network === null ||
      payment.asset === null ||
      payment.amountAtomic === null ||
      payment.walletAddress === null
    ) {
      return; // a PAID/SETTLED row always carries these; this guard keeps the types honest
    }

    await this.prisma.payment.update({ where: { id: payment.id }, data: { status: 'REFUND_PENDING' } });

    const result = await this.chain.refund({
      paymentId: payment.id,
      network: payment.network,
      asset: payment.asset,
      amountAtomic: payment.amountAtomic,
      to: payment.walletAddress,
    });

    await this.prisma.payment.update({
      where: { id: payment.id },
      data: { status: 'REFUNDED', refundTxHash: result.txHash, refundedAt: new Date() },
    });
  }
}

/** Plain JSON snapshot of the validated payload for audit. Public data only — no secrets. */
function snapshotPayload(payload: PaymentPayload): Prisma.InputJsonObject {
  return {
    x402Version: payload.x402Version,
    scheme: payload.scheme,
    network: payload.network,
    payload: {
      signature: payload.payload.signature,
      authorization: {
        from: payload.payload.authorization.from,
        to: payload.payload.authorization.to,
        value: payload.payload.authorization.value,
        validAfter: payload.payload.authorization.validAfter,
        validBefore: payload.payload.authorization.validBefore,
        nonce: payload.payload.authorization.nonce,
      },
    },
  };
}
