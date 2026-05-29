import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';

import type { ScanStatus } from '@anthrion/db';
import {
  ScanQueueProducer,
  X402_VERSION,
  paymentRequiredResponseSchema,
  type ScanJobPayload,
} from '@anthrion/shared';

import { PaymentInvalidError, PaymentNotConfiguredError } from '../payments/payment.errors';
import type { PaymentOutcome } from '../payments/payment.service';
import { PrismaService } from '../prisma/prisma.service';

import { PaymentGate } from './payment-gate';
import { PaymentRequiredException } from './payment-required.exception';
import { SCAN_QUEUE_PRODUCER } from './scan-queue.providers';
import {
  createScanRequestSchema,
  createScanResponseSchema,
  scanDetailResponseSchema,
  scanListResponseSchema,
  toDbScanType,
  toWireScanType,
  type CreateScanRequest,
  type CreateScanResponse,
  type ReportArtifactRef,
  type ScanDetailResponse,
  type ScanListResponse,
} from './scan.dto';

/**
 * Scan orchestration service (T4.1). `api` ONLY orchestrates — it validates, records,
 * and enqueues; it never runs `scan-engine` (ARCHITECTURE.md §3 — heavy work is the
 * worker's). The worker drives RUNNING → DONE/FAILED (T3.3/T3.4); this service creates
 * the QUEUED record and enqueues the job.
 */
@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly paymentGate: PaymentGate,
    @Inject(SCAN_QUEUE_PRODUCER) private readonly producer: ScanQueueProducer,
  ) {}

  /**
   * POST /scans (x402-native, T5.2): validate → create QUEUED `Scan` → run the pay gate →
   * (on success) enqueue job → return scanId. "No pay → no job" (ARCHITECTURE.md §8).
   *
   * Ordering & the chicken-and-egg with payment: `Payment.scanId` is a unique FK to `Scan`
   * (cascade), so the `Scan` is the parent and must exist before `PaymentService.authorizeScan`
   * can record the linked `Payment` (this is exactly the contract T5.1 was built and tested
   * against). So we create the QUEUED `Scan` first, then authorize:
   *
   *  - `free-pricing` / `free-trial` / `paid` → a `Payment` (FREE_PRICING / FREE_TRIAL / PAID,
   *    SETTLED) is now recorded & linked → the invariant "QUEUED scan ⇒ linked payment" holds →
   *    enqueue → 201. The job is enqueued ONLY after the payment is committed, so a job never
   *    exists without payment.
   *  - `payment-required` → no `Payment` was created → we DISCARD the just-created `Scan` and
   *    answer 402 with the x402 requirements. Final state: no scan, no payment, no job.
   *  - malformed payment (`PaymentInvalidError`) → discard the scan, reject 400 (a broken
   *    payment is a real error, not a bare 402 — the bill was already presented earlier).
   *  - facilitator not wired (`PaymentNotConfiguredError`, the T5.1 boundary) → discard the
   *    scan, reject 503 with a clear message (never a mystery 500). Unreachable by normal users
   *    in Phase 1 (price defaults to 0 → free-pricing).
   *
   * If enqueue fails AFTER the scan + payment exist, the scan is marked FAILED (Part A) and a
   * captured PAID payment is refunded, so a settled payment never bills a scan that won't run.
   *
   * Trade-off (decided & documented): on the 402/400/503 paths a `Scan` row is briefly created
   * then deleted, because `authorizeScan` requires an existing `scanId` and we do not rebuild
   * the T5.1 payment layer to split "quote" from "capture". The job is never enqueued in that
   * window, and the row is removed before responding, so the externally observable invariant
   * ("no pay → no scan, no job") holds. A process crash in the tiny pre-commit window could
   * leave a QUEUED scan with no payment and no job; it can never run (no job) and is sweepable.
   */
  async createScan(privyUserId: string, body: unknown, paymentHeader?: string): Promise<CreateScanResponse> {
    // Request body is external data — validate before use (CLAUDE.md §3). Invalid → 400.
    const parsed = createScanRequestSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({ message: 'Invalid scan request', errors: parsed.error.flatten() });
    }
    const request = parsed.data;

    const userId = await this.resolveUserId(privyUserId);
    const { targetUrl, targetKind } = describeTarget(request);

    // 1) Create the QUEUED record — the parent the `Payment` will reference.
    const scan = await this.prisma.scan.create({
      data: {
        status: 'QUEUED',
        scanType: toDbScanType(request.scanType),
        userId,
        targetUrl,
        targetKind,
      },
    });

    // 2) Pay gate — verify payment BEFORE enqueue (T5.2). `X-PAYMENT` (if any) is validated
    //    inside the payment layer (CLAUDE.md §3).
    let outcome: PaymentOutcome;
    try {
      outcome = await this.paymentGate.authorizeScan({
        scanId: scan.id,
        userId,
        scanType: request.scanType,
        resource: `/scans/${scan.id}`,
        // Omit the key entirely when absent (exactOptionalPropertyTypes) — `authorizeScan`
        // treats a missing header as "no payment attached".
        ...(paymentHeader === undefined ? {} : { paymentHeader }),
      });
    } catch (error) {
      // No `Payment` is ever created on a throw path (parse/verify/settle reject before the
      // Payment.create), so the scan is childless — discard it, then map the domain error.
      await this.discardScan(scan.id);
      if (error instanceof PaymentInvalidError) {
        throw new BadRequestException(`Invalid payment: ${error.message}`);
      }
      if (error instanceof PaymentNotConfiguredError) {
        this.logger.warn(`Payment facilitator not configured (T5.1 boundary): ${error.message}`);
        throw new ServiceUnavailableException('Payment processing is not configured yet');
      }
      throw error;
    }

    // 3) Priced scan with no settled payment → x402 402 (a NORMAL response, not an error).
    if (outcome.kind === 'payment-required') {
      await this.discardScan(scan.id);
      const responseBody = paymentRequiredResponseSchema.parse({
        x402Version: X402_VERSION,
        accepts: [outcome.requirements],
        error: 'Payment required to run this scan',
      });
      throw new PaymentRequiredException(responseBody);
    }

    // 4) Allowed (free-pricing | free-trial | paid): the `Payment` exists & is linked. Enqueue the
    //    job now — only here, so "no pay → no job" holds. Target auth (if any) rides the queue
    //    payload to the worker but is never persisted in Postgres (CLAUDE.md §7).
    try {
      await this.producer.enqueueScan(toJobPayload(scan.id, request));
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      // Do not leave a dangling QUEUED record with no job — mark it FAILED (Part A)...
      await this.prisma.scan.update({
        where: { id: scan.id },
        data: { status: 'FAILED', failureReason: `enqueue-failed: ${reason}`, finishedAt: new Date() },
      });
      // ...and refund a captured PAID payment so it does not bill a scan that won't run. The
      // `Payment` row stays consistent with the FAILED scan (no-op for FREE_*).
      await this.refundQuietly(scan.id);
      this.logger.error(`Failed to enqueue scan ${scan.id}: ${reason}`);
      throw new ServiceUnavailableException('Failed to enqueue scan job');
    }

    return createScanResponseSchema.parse({
      scanId: scan.id,
      status: 'QUEUED',
      scanType: request.scanType,
      createdAt: scan.createdAt.toISOString(),
    });
  }

  /** Remove a `Scan` that never got a settled payment (402 / malformed / facilitator boundary).
   * The scan is childless on these paths, so this is a clean delete. A delete failure is logged
   * (not swallowed silently, CLAUDE.md §3) and does not change the response the caller gets. */
  private async discardScan(scanId: string): Promise<void> {
    try {
      await this.prisma.scan.delete({ where: { id: scanId } });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to discard scan ${scanId} after payment was not completed: ${reason}`);
    }
  }

  /** Refund a captured PAID payment for a scan that cannot run, without masking the enqueue
   * failure returned to the caller. Refund execution is the T5.1 boundary (needs the treasury
   * key); if it cannot run, log that a refund is owed. No-op for FREE_* (nothing charged). */
  private async refundQuietly(scanId: string): Promise<void> {
    try {
      await this.paymentGate.refundForFailedScan(scanId);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.logger.error(`Refund for scan ${scanId} could not be executed (T5.1 boundary): ${reason}`);
    }
  }

  /** GET /scans/:id — owner-scoped detail. A scan that does not exist OR is not the
   * caller's resolves to 404 (no existence leak — Part B authorization). */
  async getScanById(privyUserId: string, scanId: string): Promise<ScanDetailResponse> {
    const userId = await this.resolveUserId(privyUserId);
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, userId },
      include: {
        findings: { orderBy: { createdAt: 'asc' } },
        // Payment kind + status only (T5.4 Part 1). NEVER the on-chain payload / proof columns
        // (rawPayload, settleTxHash, …) — those must not cross the wire (CLAUDE.md §7).
        payment: { select: { kind: true, status: true } },
        // Just enough to know a report PDF exists (T6.1) — count, not the blob reference.
        artifacts: { where: { type: 'REPORT_PDF' }, select: { id: true } },
      },
    });
    if (scan === null) {
      throw new NotFoundException('Scan not found');
    }

    return scanDetailResponseSchema.parse({
      id: scan.id,
      status: scan.status,
      scanType: toWireScanType(scan.scanType),
      targetUrl: scan.targetUrl,
      targetKind: scan.targetKind,
      failureReason: scan.failureReason,
      createdAt: scan.createdAt.toISOString(),
      startedAt: scan.startedAt?.toISOString() ?? null,
      finishedAt: scan.finishedAt?.toISOString() ?? null,
      // DB enum casing == wire casing (like ScanStatus), so kind/status pass straight through.
      payment: scan.payment === null ? null : { kind: scan.payment.kind, status: scan.payment.status },
      reportAvailable: scan.artifacts.length > 0,
      // Persisted by the worker when it generated the PDF (T6.2). Pass it as-is into the
      // detail schema; `scanDetailResponseSchema.parse` below applies the Zod boundary
      // (CLAUDE.md §3) — a malformed value fails loudly here, never reaches the client.
      reportCoverage: scan.reportCoverage,
      findings: scan.findings.map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        category: finding.category,
        title: finding.title,
        description: finding.description,
        evidence: finding.evidence,
        recommendation: finding.recommendation,
      })),
    });
  }

  /**
   * GET /scans/:id/report — resolve the report PDF artifact for a scan the caller owns
   * (T6.1). Authorization mirrors `getScanById` (Part B): a scan that does not exist OR is
   * not the caller's resolves to 404 (no existence leak). A scan with no report artifact
   * (FAILED, or report generation failed) also resolves to 404 — a clear "not available"
   * answer, never a 500. Returns the MinIO object reference for the controller to stream.
   */
  async getReportArtifactForOwner(privyUserId: string, scanId: string): Promise<ReportArtifactRef> {
    const userId = await this.resolveUserId(privyUserId);
    // Owner-scope the artifact lookup in one query: an artifact only matches when its scan
    // belongs to this user, so a non-owner / missing scan yields no row → 404.
    const artifact = await this.prisma.artifact.findFirst({
      where: { type: 'REPORT_PDF', scan: { id: scanId, userId } },
      orderBy: { createdAt: 'desc' },
      select: { bucket: true, objectKey: true, contentType: true, sizeBytes: true },
    });
    if (artifact === null) {
      throw new NotFoundException('Report not available for this scan');
    }
    return artifact;
  }

  /** GET /scans — the caller's own scans (newest first). */
  async listScans(privyUserId: string): Promise<ScanListResponse> {
    const userId = await this.resolveUserId(privyUserId);
    const scans = await this.prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });

    return scanListResponseSchema.parse({
      scans: scans.map((scan) => ({
        id: scan.id,
        status: scan.status,
        scanType: toWireScanType(scan.scanType),
        targetUrl: scan.targetUrl,
        createdAt: scan.createdAt.toISOString(),
        finishedAt: scan.finishedAt?.toISOString() ?? null,
      })),
    });
  }

  /** GET /scans/:id/stream — owner-scoped current status (T4.2). 404 if not owned/found
   * (no existence leak, like getScanById). Used to authorize the SSE stream and to seed
   * its initial snapshot. */
  async getOwnedScanStatus(privyUserId: string, scanId: string): Promise<ScanStatus> {
    const userId = await this.resolveUserId(privyUserId);
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, userId },
      select: { status: true },
    });
    if (scan === null) {
      throw new NotFoundException('Scan not found');
    }
    return scan.status;
  }

  /** Resolve the DB user id for an authenticated Privy user (synced by the global
   * UserSyncInterceptor before the handler runs). Missing → treat as auth failure. */
  private async resolveUserId(privyUserId: string): Promise<string> {
    const user = await this.prisma.user.findUnique({
      where: { privyUserId },
      select: { id: true },
    });
    if (user === null) {
      throw new UnauthorizedException('Authenticated user not found');
    }
    return user.id;
  }
}

/** Non-sensitive target info stored on the `Scan` row (never auth secrets, CLAUDE.md §7). */
function describeTarget(request: CreateScanRequest): { targetUrl: string | null; targetKind: string | null } {
  if (request.scanType === 'web-app-vuln') {
    return { targetUrl: request.target.url, targetKind: null };
  }
  if (request.scanType === 'api-scan') {
    if (request.target.kind === 'raw') {
      return { targetUrl: request.target.url, targetKind: 'api-raw' };
    }
    // Spec mode: no single endpoint URL (the document carries N operations); baseUrl
    // is optional, and we never persist the spec document itself.
    return { targetUrl: request.target.baseUrl ?? null, targetKind: 'api-spec' };
  }
  if (request.scanType === 'web3-dapp') {
    // Sprint A3 (T-A3.7): chain is non-sensitive metadata; targetKind carries it so
    // /scans listings can distinguish ethereum vs base scans without re-fetching.
    return { targetUrl: request.target.url, targetKind: `web3-${request.target.chain}` };
  }
  if (request.target.kind === 'endpoint') {
    return { targetUrl: request.target.url, targetKind: 'endpoint' };
  }
  return { targetUrl: null, targetKind: 'system-prompt' };
}

/** Build the queue payload from the created scan id + the validated request. */
function toJobPayload(scanId: string, request: CreateScanRequest): ScanJobPayload {
  if (request.scanType === 'web-app-vuln') {
    // Sprint A2: forward the optional crawl budget. Absent → single-page (Phase 1
    // behavior preserved); present → the worker maps it to crawl mode.
    return {
      scanId,
      scanType: 'web-app-vuln',
      target: request.target,
      ...(request.crawl !== undefined ? { crawl: request.crawl } : {}),
    };
  }
  if (request.scanType === 'api-scan') {
    return { scanId, scanType: 'api-scan', target: request.target };
  }
  if (request.scanType === 'web3-dapp') {
    // Sprint A3 (T-A3.7 → T-A3.8): forward url + chain + optional wallet-
    // interaction depth (engine applies DEFAULT_WEB3_WALLET_INTERACTION_DEPTH
    // when absent). NO private-key / mnemonic / wallet-connect field by
    // construction (sub-agent rubric §10).
    return { scanId, scanType: 'web3-dapp', target: request.target };
  }
  return { scanId, scanType: 'ai-llm-attack', target: request.target };
}
