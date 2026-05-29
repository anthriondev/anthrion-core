import type { ReportCoverage } from '@anthrion/shared';

import type { ScanRunSucceeded } from '../scan-runner';
import type { ArtifactRef, ArtifactStore } from '../storage/artifact-store';

import { buildReportModel, type ReportScanMeta } from './report-model';
import { renderReportPdf } from './pdf-renderer';
import {
  REPORT_PDF_MARGIN,
  renderFooterTemplate,
  renderHeaderTemplate,
  renderReportHtml,
} from './report-template';

/**
 * PDF report generation step (T6.1) — runs at the end of a SUCCESSFUL scan job, after
 * findings are persisted and the scan is DONE (timing: eager, locked decision).
 *
 * Failure policy (locked decision + CLAUDE.md §3): this is best-effort. If anything here
 * fails it MUST NOT flip the scan to FAILED and MUST NOT block findings — it logs the
 * error explicitly (never a silent catch) and returns, leaving the scan DONE with no
 * report artifact. The api/UI then surface "report unavailable" honestly. It is only ever
 * invoked for success states; FAILED scans get no PDF (handled in T6.2).
 */

/** DB surface the report step needs — implemented by `ScanRepository`. */
export interface ReportStore {
  getReportScanMeta(scanId: string): Promise<ReportScanMeta | null>;
  /** Record the report artifact AND the coverage summary atomically (T6.2 — UI/PDF
   * share one source of truth). */
  recordReportArtifact(scanId: string, ref: ArtifactRef, coverage: ReportCoverage): Promise<void>;
}

export interface GenerateReportDeps {
  store: ReportStore;
  artifacts: ArtifactStore;
  /**
   * PDF renderer — defaults to the real Playwright renderer. Injectable so unit tests can
   * exercise the build→store path without launching Chromium.
   */
  renderPdf?: (html: string) => Promise<Buffer>;
}

/**
 * Build the report model from a successful scan, render it to HTML → PDF, upload to MinIO
 * and record the (single) REPORT_PDF artifact. Returns the stored ref, or null when the
 * step was skipped/failed (never throws).
 */
export async function generateScanReport(
  deps: GenerateReportDeps,
  result: ScanRunSucceeded,
): Promise<ArtifactRef | null> {
  try {
    const meta = await deps.store.getReportScanMeta(result.scanId);
    if (meta === null) {
      // The scan was just persisted, so this should not happen; if it does, report it
      // rather than throwing — the scan itself stands.
      console.error(`[worker] report generation skipped for scan ${result.scanId} — scan row not found`);
      return null;
    }

    const model = buildReportModel({ meta, findings: result.findings, report: result.report });
    const html = renderReportHtml(model);
    // T-POLISH.2: running header/footer in the page-margin band on every page.
    const headerTemplate = renderHeaderTemplate(model);
    const footerTemplate = renderFooterTemplate(model);
    const render =
      deps.renderPdf ??
      ((markup: string) =>
        renderReportPdf(markup, { headerTemplate, footerTemplate, margin: REPORT_PDF_MARGIN }));
    const pdf = await render(html);

    const ref = await deps.artifacts.uploadReportPdf(result.scanId, pdf);
    // Coverage from the model is the same value the PDF renders — persisting it on the
    // Scan row gives the UI and the PDF one source of truth (T6.2).
    await deps.store.recordReportArtifact(result.scanId, ref, model.coverage);

    console.log(
      `[worker] report PDF stored for scan ${result.scanId} — ${ref.sizeBytes} bytes` +
        (model.coverage.complete ? '' : ` (partial coverage: ${model.coverage.gaps.map((gap) => gap.kind).join(', ')})`),
    );
    return ref;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    console.error(
      `[worker] report generation failed for scan ${result.scanId} — scan stays DONE without a report: ${message}`,
    );
    return null;
  }
}
