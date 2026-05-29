'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

import type { ScanDetailResponse, ScanStatusWire } from '@anthrion/shared/scan-api';
import type { ScanStreamEvent } from '@anthrion/shared/scan-stream';

import type { ScanApiClient } from '../../../lib/api-client';
import { consumeScanStream } from '../../../lib/scan-stream';

import { PageShell } from './PageShell';
import { ScanDetailView } from './ScanDetailView';

export interface ScanDetailScreenProps {
  scanId: string;
  client: ScanApiClient;
  getToken: () => Promise<string | null>;
  baseUrl: string;
}

type LoadState =
  | { kind: 'loading' }
  | { kind: 'not-found' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; detail: ScanDetailResponse };

function isTerminal(status: ScanStatusWire): boolean {
  return status === 'DONE' || status === 'FAILED';
}

/**
 * Append an SSE event, dropping a duplicate consecutive lifecycle status — e.g. the
 * snapshot seeded from `getScan` matching the lifecycle snapshot the SSE endpoint emits
 * on connect. This reconciles the initial snapshot with the live stream.
 */
function appendEvent(events: ScanStreamEvent[], event: ScanStreamEvent): ScanStreamEvent[] {
  const last = events[events.length - 1];
  if (event.type === 'lifecycle' && last !== undefined && last.type === 'lifecycle' && last.status === event.status) {
    return events;
  }
  return [...events, event];
}

/**
 * Container: scan detail + real-time progress.
 *
 * Snapshot vs live: `getScan` gives the status at page load and seeds the event log with
 * a lifecycle event; the SSE stream is opened ONLY when that snapshot is non-terminal
 * (an already-finished scan shows its final state immediately — no hanging on SSE). The
 * stream then appends live events and drives the live status. Cleanup aborts the stream
 * on unmount.
 */
export function ScanDetailScreen({ scanId, client, getToken, baseUrl }: ScanDetailScreenProps): React.ReactElement {
  const [load, setLoad] = useState<LoadState>({ kind: 'loading' });
  const [status, setStatus] = useState<ScanStatusWire>('QUEUED');
  const [events, setEvents] = useState<ScanStreamEvent[]>([]);
  const [streamError, setStreamError] = useState<string | null>(null);

  // 1) Initial snapshot.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await client.getScan(scanId);
      if (cancelled) {
        return;
      }
      if (result.ok) {
        setLoad({ kind: 'ready', detail: result.data });
        setStatus(result.data.status);
        setEvents([{ type: 'lifecycle', status: result.data.status }]);
      } else if (result.error.kind === 'http' && result.error.status === 404) {
        setLoad({ kind: 'not-found' });
      } else {
        setLoad({ kind: 'error', message: result.error.message });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, scanId]);

  // 2) Live SSE — only while the snapshot status is non-terminal.
  const snapshotStatus = load.kind === 'ready' ? load.detail.status : null;
  useEffect(() => {
    if (snapshotStatus === null || isTerminal(snapshotStatus)) {
      return; // finished at load → final state already shown; do not open a stream
    }
    const controller = new AbortController();
    let refreshed = false;
    void consumeScanStream({
      baseUrl,
      scanId,
      getToken,
      signal: controller.signal,
      onEvent: (event) => {
        setEvents((prev) => appendEvent(prev, event));
        if (event.type !== 'lifecycle') {
          return;
        }
        setStatus(event.status);
        // The SSE stream carries PROGRESS, not findings. When the scan completes live,
        // re-fetch to load the persisted findings (T3.4) the report will render. Guarded
        // so it runs once. (This is the one extra call beyond T4.3c, and it is needed.)
        if ((event.status === 'DONE' || event.status === 'FAILED') && !refreshed) {
          refreshed = true;
          void (async () => {
            const result = await client.getScan(scanId);
            if (result.ok) {
              setLoad({ kind: 'ready', detail: result.data });
            }
          })();
        }
      },
      onError: (error) => setStreamError(error.message),
    });
    return () => controller.abort(); // cleanup on unmount — no dangling connection
  }, [snapshotStatus, scanId, baseUrl, getToken, client]);

  if (load.kind === 'loading') {
    return (
      <PageShell>
        <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Loading scan…</p>
      </PageShell>
    );
  }

  if (load.kind === 'not-found') {
    return (
      <PageShell>
        <BackLink />
        <p className="mt-6 text-h3 text-ice">Scan not found</p>
        <p className="mt-2 text-small text-text-secondary">
          This scan does not exist, or it belongs to another account.
        </p>
      </PageShell>
    );
  }

  if (load.kind === 'error') {
    return (
      <PageShell>
        <BackLink />
        <p className="mt-6 text-small text-text-secondary">Could not load this scan.</p>
        <p data-testid="detail-error" className="mt-2 font-mono text-caption text-magenta-core">
          {load.message}
        </p>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <ScanDetailView detail={load.detail} status={status} events={events} streamError={streamError} client={client} />
    </PageShell>
  );
}

function BackLink(): React.ReactElement {
  return (
    <Link href="/scans" className="font-mono text-caption uppercase tracking-wide text-text-muted hover:text-ice">
      ← All scans
    </Link>
  );
}
