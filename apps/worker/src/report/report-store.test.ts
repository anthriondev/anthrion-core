import '../test-env'; // MUST be first: sets env before '@anthrion/shared' validates it.

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { Client as MinioClient } from 'minio';

import { createPrismaClient, type PrismaClient } from '@anthrion/db';
import type { Finding } from '@anthrion/scan-engine';
import type { ScanReport } from '@anthrion/sandbox-runtime';
import { env, reportCoverageSchema } from '@anthrion/shared';

import { ScanRepository } from '../persistence/scan-repository';
import type { ScanRunSucceeded } from '../scan-runner';
import { MinioArtifactStore } from '../storage/artifact-store';

import { generateScanReport } from './generate-report';
import { renderReportHtml } from './report-template';
import { buildReportModel } from './report-model';
import { renderReportPdf } from './pdf-renderer';

/**
 * Report storage tests (T6.1) — REAL Postgres + MinIO + REAL Chromium.
 *
 * Proves the worker half of the vertical slice: build → render PDF → upload to MinIO →
 * record a single REPORT_PDF artifact. Also proves the best-effort failure contract (a
 * render failure leaves the scan DONE with no artifact and never throws) and idempotency
 * (regeneration keeps exactly one report per scan).
 */

const prisma: PrismaClient = createPrismaClient(env.DATABASE_URL);
const artifacts = new MinioArtifactStore();
const repo = new ScanRepository(prisma);
const minioVerify = new MinioClient({
  endPoint: env.MINIO_ENDPOINT,
  port: env.MINIO_PORT,
  useSSL: false,
  accessKey: env.MINIO_ACCESS_KEY,
  secretKey: env.MINIO_SECRET_KEY,
});

const aiReport: ScanReport = {
  scanType: 'ai-llm-attack',
  passedLayer1: true,
  layer1Outcome: 'passed',
  layer1Stats: { total: 10, executed: 10, detected: 1, clean: 9, notExecuted: 0 },
  layer2Ran: true,
  layer2StoppedReason: 'budget-exhausted',
  budgetUsed: 20000,
  budgetCap: 20000,
};

const finding: Finding = {
  id: 'layer1:pi',
  severity: 'High',
  category: 'prompt-injection',
  title: 'Prompt injection',
  description: 'Override succeeded.',
  evidence: { input: 'ignore instructions', output: 'ok', metadata: { target_model: 'gpt-4o' } },
  recommendation: 'Enforce instruction hierarchy.',
};

function succeeded(scanId: string): ScanRunSucceeded {
  return { status: 'succeeded', scanId, scanType: 'ai-llm-attack', findings: [finding], report: aiReport, durationMs: 10 };
}

async function readObject(bucket: string, key: string): Promise<Buffer> {
  const stream = await minioVerify.getObject(bucket, key);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

// ── Pure: the PDF renderer produces a valid PDF (real Chromium) ────────────────

test('renderReportPdf produces a valid PDF document (real Chromium)', { timeout: 60_000 }, async () => {
  const model = buildReportModel({
    meta: { scanId: 'render_only', targetUrl: 'https://x.example', targetKind: 'endpoint', startedAt: new Date(), finishedAt: new Date() },
    findings: [finding],
    report: aiReport,
  });
  const pdf = await renderReportPdf(renderReportHtml(model));
  assert.ok(pdf.length > 1000, 'PDF has real content');
  assert.equal(pdf.subarray(0, 5).toString('latin1'), '%PDF-', 'starts with the PDF magic header');
});

describe('report storage (real Postgres + MinIO)', () => {
  let skipReason: string | undefined;
  let userId = '';
  const createdScanIds: string[] = [];

  async function createDoneScan(): Promise<string> {
    const scan = await prisma.scan.create({
      data: { status: 'QUEUED', scanType: 'AI_LLM_ATTACK', userId, targetUrl: 'https://agent.example', targetKind: 'endpoint' },
    });
    createdScanIds.push(scan.id);
    await repo.markRunning(scan.id);
    await repo.saveSucceeded(scan.id, [finding]); // → DONE + finishedAt + findings
    return scan.id;
  }

  before(async () => {
    try {
      await prisma.$connect();
      await artifacts.ensureBucket();
      const user = await prisma.user.create({ data: { privyUserId: `t6.1-test-${Date.now()}` } });
      userId = user.id;
    } catch (cause) {
      skipReason = `infra unavailable (Postgres/MinIO): ${cause instanceof Error ? cause.message : String(cause)}`;
    }
  });

  after(async () => {
    if (skipReason === undefined) {
      await prisma.scan.deleteMany({ where: { id: { in: createdScanIds } } });
      if (userId !== '') {
        await prisma.user.delete({ where: { id: userId } }).catch(() => undefined);
      }
    }
    await prisma.$disconnect();
  });

  test('generateScanReport stores a real PDF in MinIO and records ONE REPORT_PDF artifact', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = await createDoneScan();
    const ref = await generateScanReport({ store: repo, artifacts }, succeeded(scanId));
    assert.ok(ref, 'a report artifact ref was returned');

    // Exactly one REPORT_PDF artifact row, distinct from the scan-log path.
    const rows = await prisma.artifact.findMany({ where: { scanId, type: 'REPORT_PDF' } });
    assert.equal(rows.length, 1);
    const row = rows[0];
    assert.ok(row);
    assert.equal(row.contentType, 'application/pdf');
    assert.equal(row.objectKey, `scans/${scanId}/report.pdf`);

    // The object really exists in MinIO, with the recorded size and a real PDF body.
    const stat = await minioVerify.statObject(row.bucket, row.objectKey);
    assert.equal(stat.size, row.sizeBytes);
    const bytes = await readObject(row.bucket, row.objectKey);
    assert.equal(bytes.subarray(0, 5).toString('latin1'), '%PDF-');
    // §7: the target model name from the finding metadata is not embedded anywhere obvious.
    assert.equal(bytes.includes(Buffer.from('gpt-4o')), false);

    // The scan itself stays DONE and carries the coverage summary the PDF used (T6.2).
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    assert.equal(scan.status, 'DONE');
    assert.ok(scan.reportCoverage !== null, 'reportCoverage is persisted on the Scan row');
    // Validate the JSON shape the same way the api will on read — never an `as` of DB data.
    const coverage = reportCoverageSchema.parse(scan.reportCoverage);
    // The sample fixture sets `layer2StoppedReason: 'budget-exhausted'` → the budget gap kind.
    assert.equal(coverage.complete, false);
    assert.deepEqual(coverage.gaps.map((gap) => gap.kind), ['ai-layer2-budget-exhausted']);
  });

  test('regenerating keeps exactly one report artifact (idempotent)', async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = await createDoneScan();
    // Stub the renderer to keep this fast — the real render is covered above.
    const renderPdf = (): Promise<Buffer> => Promise.resolve(Buffer.from('%PDF-1.7\nstub'));
    await generateScanReport({ store: repo, artifacts, renderPdf }, succeeded(scanId));
    await generateScanReport({ store: repo, artifacts, renderPdf }, succeeded(scanId));
    const rows = await prisma.artifact.findMany({ where: { scanId, type: 'REPORT_PDF' } });
    assert.equal(rows.length, 1, 'still exactly one report artifact after regeneration');
  });

  test('a render failure leaves the scan DONE with no report artifact and never throws', async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const scanId = await createDoneScan();
    const renderPdf = (): Promise<Buffer> => Promise.reject(new Error('chromium boom'));
    const ref = await generateScanReport({ store: repo, artifacts, renderPdf }, succeeded(scanId));
    assert.equal(ref, null, 'no artifact ref on failure');
    const rows = await prisma.artifact.findMany({ where: { scanId, type: 'REPORT_PDF' } });
    assert.equal(rows.length, 0, 'no report artifact recorded on failure');
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    assert.equal(scan.status, 'DONE', 'the successful scan is untouched');
  });
});
