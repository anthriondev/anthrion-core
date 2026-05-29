import Link from 'next/link';

import type { ScanDetailResponse, ScanStatusWire } from '@anthrion/shared/scan-api';
import type { ScanStreamEvent } from '@anthrion/shared/scan-stream';
import { Card, cn, ScanProgress } from '@anthrion/ui';

import type { ScanApiClient } from '../../../lib/api-client';

import { CoverageBanner } from './CoverageBanner';
import { DownloadReportButton } from './DownloadReportButton';
import { FindingsSection } from './FindingsSection';
import { ScanPaymentChip } from './ScanPaymentChip';
import { ScanStatusChip } from './ScanStatusChip';
import { Web3FindingsSections } from './Web3FindingsSections';
import { formatTimestamp, scanTypeLabel, targetSummary } from './scan-display';

/** Presentational scan detail — pure, props-driven. Status & events flow in from the container. */
export interface ScanDetailViewProps {
  detail: ScanDetailResponse;
  status: ScanStatusWire;
  events: ScanStreamEvent[];
  streamError: string | null;
  /** Scan API client — used by the report download action (T6.1). */
  client: ScanApiClient;
}

export function ScanDetailView({ detail, status, events, streamError, client }: ScanDetailViewProps): React.ReactElement {
  return (
    <div className="flex flex-col gap-8">
      <Link href="/scans" className="font-mono text-caption uppercase tracking-wide text-text-muted hover:text-ice">
        ← All scans
      </Link>

      <header className="flex flex-col gap-4">
        {/* Mobile: stack the title above the action row so the download button + status
            chip cannot clip the title on narrow viewports (DESIGN_SYSTEM.md §8). */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
          <h1 className="text-h2 font-semibold text-ice">{scanTypeLabel(detail.scanType)}</h1>
          <div className="flex flex-wrap items-center gap-3">
            {/* Report download (T6.1): only when a report artifact exists — never a broken
                button. A DONE scan with no report shows an honest note instead (below). */}
            {status === 'DONE' && detail.reportAvailable ? (
              <DownloadReportButton client={client} scanId={detail.id} />
            ) : null}
            <ScanStatusChip status={status} />
          </div>
        </div>
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Meta label="Target" value={targetSummary(detail.targetUrl, detail.targetKind)} mono />
          <Meta label="Created" value={formatTimestamp(detail.createdAt)} />
          <Meta label="Scan ID" value={detail.id} mono />
        </dl>

        {/* Payment kind + status — real data from the scan's Payment record (T5.4 Part 1). */}
        <div className="flex flex-col gap-1">
          <span className="font-mono text-caption uppercase tracking-wide text-text-muted">Payment</span>
          <div>
            <ScanPaymentChip payment={detail.payment} />
          </div>
        </div>
      </header>

      <ScanProgress events={events} status={status} />

      {streamError !== null ? (
        <p data-testid="stream-error" className="font-mono text-caption text-magenta-core">
          Live updates interrupted: {streamError}
        </p>
      ) : null}

      {/* Coverage banner (T6.2): shows per-type incomplete-coverage notes for DONE scans,
          mirroring the PDF. Null `reportCoverage` (legacy / never-generated) renders nothing —
          honest neutrality, never a claim of completeness (CLAUDE.md §3). */}
      {status === 'DONE' ? <CoverageBanner coverage={detail.reportCoverage} /> : null}
      {status === 'DONE' ? (
        detail.scanType === 'web3-dapp' ? (
          // Sprint A3 T-A3.8: render the three Web3 layers separately so the
          // report reads as three distinct concerns rather than one merged list.
          <Web3FindingsSections findings={detail.findings} />
        ) : (
          <FindingsSection findings={detail.findings} />
        )
      ) : null}
      {/* DONE but no report artifact (PDF generation failed): say so honestly rather than
          showing a broken/again button (T6.1). FAILED scans never claim a report. */}
      {status === 'DONE' && !detail.reportAvailable ? (
        <p data-testid="report-unavailable" className="font-mono text-caption uppercase tracking-wide text-text-muted">
          PDF report unavailable for this scan.
        </p>
      ) : null}
      {status === 'FAILED' ? <FailurePanel reason={detail.failureReason} /> : null}
    </div>
  );
}

function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }): React.ReactElement {
  return (
    <div className="flex flex-col gap-1">
      <dt className="font-mono text-caption uppercase tracking-wide text-text-muted">{label}</dt>
      <dd className={cn('text-small text-ice', mono ? 'break-all font-mono' : '')}>{value}</dd>
    </div>
  );
}

/** Failure is shown honestly with its reason — a failed scan is never rendered as empty/safe. */
function FailurePanel({ reason }: { reason: string | null }): React.ReactElement {
  return (
    <Card data-testid="failure-panel" className="border-severity-critical/40">
      <div className="flex flex-col gap-2 py-2">
        <p className="text-h3 text-severity-critical">Scan failed</p>
        <p className="text-small text-text-secondary">
          {reason !== null && reason !== '' ? reason : 'The scan failed without a reported reason.'}
        </p>
      </div>
    </Card>
  );
}
