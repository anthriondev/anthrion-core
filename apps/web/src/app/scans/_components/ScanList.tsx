import Link from 'next/link';

import type { ScanSummaryResponse } from '@anthrion/shared/scan-api';
import { buttonClassName, Card } from '@anthrion/ui';

import { ScanStatusChip } from './ScanStatusChip';
import { formatTimestamp, scanTypeLabel, targetSummary } from './scan-display';

/** Presentational scan list — pure, driven by `state` (loading/error/ready). */
export type ScanListState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; scans: ScanSummaryResponse[] };

export function ScanList({ state }: { state: ScanListState }): React.ReactElement {
  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
        <h1 className="text-h2 font-semibold text-ice">Scans</h1>
        <Link href="/scans/new" className={`${buttonClassName({ variant: 'primary' })} self-start sm:self-auto`}>
          New scan
        </Link>
      </header>
      {renderBody(state)}
    </div>
  );
}

function renderBody(state: ScanListState): React.ReactElement {
  if (state.kind === 'loading') {
    return <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Loading scans…</p>;
  }

  if (state.kind === 'error') {
    return (
      <Card data-testid="list-error">
        <p className="text-small text-text-secondary">Could not load scans.</p>
        <p className="mt-2 font-mono text-caption text-magenta-core">{state.message}</p>
      </Card>
    );
  }

  if (state.scans.length === 0) {
    return (
      <Card withMarks data-testid="list-empty">
        <div className="flex flex-col items-start gap-4 py-6">
          <p className="text-h3 text-ice">No scans yet</p>
          <p className="max-w-prose text-small text-text-secondary">
            Start your first AI/LLM attack scan or web app vulnerability scan.
          </p>
          <Link href="/scans/new" className={buttonClassName({ variant: 'primary' })}>
            Create your first scan
          </Link>
        </div>
      </Card>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {state.scans.map((scan) => (
        <li key={scan.id}>
          <Link href={`/scans/${scan.id}`} className="block">
            <Card className="transition-colors duration-base ease-out hover:border-magenta-core/40">
              {/* Mobile: stack rows so the right column (status + timestamp) cannot squeeze
                  the target URL or get clipped (DESIGN_SYSTEM.md §8). At sm+ revert to the
                  side-by-side desktop layout. The min-w-0 on the left column lets the
                  flex parent honour text-truncation on long URLs. */}
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                <div className="flex min-w-0 flex-col gap-1">
                  <span className="text-small text-ice">{scanTypeLabel(scan.scanType)}</span>
                  <span className="break-all font-mono text-caption text-text-muted">{targetSummary(scan.targetUrl, null)}</span>
                </div>
                <div className="flex flex-wrap items-center gap-3 sm:shrink-0 sm:flex-col sm:items-end sm:gap-1">
                  <ScanStatusChip status={scan.status} />
                  <span className="font-mono text-caption text-text-muted">{formatTimestamp(scan.createdAt)}</span>
                </div>
              </div>
            </Card>
          </Link>
        </li>
      ))}
    </ul>
  );
}
