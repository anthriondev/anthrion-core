import type { ArtifactType, FindingSeverity, Prisma, PrismaClient } from '@anthrion/db';
import type { Finding, Severity } from '@anthrion/scan-engine';
import { reportCoverageSchema, type ReportCoverage } from '@anthrion/shared';

import type { ReportScanMeta } from '../report/report-model';
import type { ScanFailureReason } from '../scan-runner';
import type { ArtifactRef } from '../storage/artifact-store';

/**
 * Scan persistence (T3.4, Part C). The worker — NOT the pure scan-engine /
 * sandbox-runtime (ARCHITECTURE.md §2) — owns DB writes. Drives the status
 * transitions RUNNING → DONE/FAILED and stores `Finding`s + artifact references.
 *
 * Status creation (QUEUED) is `api`'s job at `POST /scans` (T4.1); the worker only
 * transitions a pre-existing `Scan` row.
 */

/** Persistence surface the worker depends on (interface → stubbable in unit tests). */
export interface ScanResultStore {
  markRunning(scanId: string): Promise<void>;
  saveSucceeded(scanId: string, findings: readonly Finding[]): Promise<void>;
  saveFailed(scanId: string, reason: ScanFailureReason, message: string): Promise<void>;
  addArtifact(scanId: string, type: ArtifactType, ref: ArtifactRef): Promise<void>;
}

/** Engine severity → DB enum. Exhaustive over `Severity`, so no value is lost. */
const SEVERITY_MAP: Record<Severity, FindingSeverity> = {
  Critical: 'CRITICAL',
  High: 'HIGH',
  Medium: 'MEDIUM',
  Low: 'LOW',
  Info: 'INFO',
};

export class ScanRepository implements ScanResultStore {
  constructor(private readonly prisma: PrismaClient) {}

  /** QUEUED → RUNNING when execution begins (Part C.1). */
  async markRunning(scanId: string): Promise<void> {
    await this.prisma.scan.update({
      where: { id: scanId },
      data: { status: 'RUNNING', startedAt: new Date() },
    });
  }

  /**
   * Success: write findings and flip the scan to DONE in ONE transaction, so a scan is
   * never DONE without its findings (or vice versa).
   */
  async saveSucceeded(scanId: string, findings: readonly Finding[]): Promise<void> {
    const data = findings.map((finding) => this.toFindingRow(scanId, finding));
    await this.prisma.$transaction([
      this.prisma.finding.createMany({ data }),
      this.prisma.scan.update({
        where: { id: scanId },
        data: { status: 'DONE', finishedAt: new Date() },
      }),
    ]);
  }

  /**
   * Failure: FAILED + the reason. NEVER stored as "DONE with 0 findings" — a failed or
   * truncated scan is not a clean bill (Context §3, consistent since T2.3).
   */
  async saveFailed(scanId: string, reason: ScanFailureReason, message: string): Promise<void> {
    await this.prisma.scan.update({
      where: { id: scanId },
      data: { status: 'FAILED', failureReason: `${reason}: ${message}`, finishedAt: new Date() },
    });
  }

  async addArtifact(scanId: string, type: ArtifactType, ref: ArtifactRef): Promise<void> {
    await this.prisma.artifact.create({
      data: {
        scanId,
        type,
        bucket: ref.bucket,
        objectKey: ref.objectKey,
        contentType: ref.contentType,
        sizeBytes: ref.sizeBytes,
      },
    });
  }

  /** Read the non-sensitive scan metadata the PDF report needs (T6.1). Null if the scan
   * row is gone. Never selects target auth secrets — they are not stored (CLAUDE.md §7). */
  async getReportScanMeta(scanId: string): Promise<ReportScanMeta | null> {
    const scan = await this.prisma.scan.findUnique({
      where: { id: scanId },
      select: { id: true, targetUrl: true, targetKind: true, startedAt: true, finishedAt: true },
    });
    if (scan === null) {
      return null;
    }
    return {
      scanId: scan.id,
      targetUrl: scan.targetUrl,
      targetKind: scan.targetKind,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
    };
  }

  /** Record the single REPORT_PDF artifact for a scan AND persist its coverage summary on
   * the `Scan` row (T6.1 + T6.2). Idempotent: any existing report row is removed first,
   * so a regenerated report never leaves duplicates — exactly one report artifact per
   * scan, matching the deterministic MinIO object key.
   *
   * Coverage is validated with Zod before it is written so the JSON column can never carry
   * a malformed shape (CLAUDE.md §3 — boundary validation, not assertion). One transaction
   * keeps the artifact row and the coverage value strictly in sync: a scan never has the
   * REPORT_PDF artifact without its matching coverage, and vice versa. */
  async recordReportArtifact(scanId: string, ref: ArtifactRef, coverage: ReportCoverage): Promise<void> {
    const validatedCoverage = reportCoverageSchema.parse(coverage);
    await this.prisma.$transaction([
      this.prisma.artifact.deleteMany({ where: { scanId, type: 'REPORT_PDF' } }),
      this.prisma.artifact.create({
        data: {
          scanId,
          type: 'REPORT_PDF',
          bucket: ref.bucket,
          objectKey: ref.objectKey,
          contentType: ref.contentType,
          sizeBytes: ref.sizeBytes,
        },
      }),
      this.prisma.scan.update({
        where: { id: scanId },
        data: { reportCoverage: validatedCoverage as Prisma.InputJsonValue },
      }),
    ]);
  }

  /** Map an engine `Finding` → a Prisma `Finding` create row, losslessly (Context §3). */
  private toFindingRow(scanId: string, finding: Finding): Prisma.FindingCreateManyInput {
    // Evidence is a self-contained structured blob → JSON column. metadata is included
    // only when present (JSON has no `undefined`).
    const evidence: Prisma.InputJsonValue = {
      input: finding.evidence.input,
      output: finding.evidence.output,
      ...(finding.evidence.metadata !== undefined ? { metadata: finding.evidence.metadata } : {}),
    };
    return {
      scanId,
      engineId: finding.id,
      severity: SEVERITY_MAP[finding.severity],
      category: finding.category,
      title: finding.title,
      description: finding.description,
      evidence,
      recommendation: finding.recommendation,
    };
  }
}
