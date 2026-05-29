'use client';

import { useState } from 'react';

import { Button } from '@anthrion/ui';

import type { ScanApiClient } from '../../../lib/api-client';

/**
 * Download the PDF security report for a scan (T6.1). Shown only when the report artifact
 * exists (`detail.reportAvailable`), so there is never a broken button.
 *
 * The endpoint is auth-protected, so a plain `<a href>` cannot carry the bearer token —
 * we fetch the PDF as a blob (token attached by the api client) and trigger a download.
 * Failures are surfaced inline, never swallowed (CLAUDE.md §3).
 */
export interface DownloadReportButtonProps {
  client: ScanApiClient;
  scanId: string;
}

type DownloadState = 'idle' | 'downloading' | 'error';

export function DownloadReportButton({ client, scanId }: DownloadReportButtonProps): React.ReactElement {
  const [state, setState] = useState<DownloadState>('idle');
  const [error, setError] = useState<string | null>(null);

  async function handleDownload(): Promise<void> {
    setState('downloading');
    setError(null);
    const result = await client.downloadReportPdf(scanId);
    if (!result.ok) {
      setState('error');
      setError(result.error.message);
      return;
    }
    triggerBrowserDownload(result.data, `anthrion-report-${scanId}.pdf`);
    setState('idle');
  }

  return (
    <div data-testid="download-report" className="flex flex-col items-end gap-1">
      <Button
        variant="secondary"
        size="sm"
        onClick={() => void handleDownload()}
        disabled={state === 'downloading'}
      >
        {state === 'downloading' ? 'Preparing PDF…' : 'Download PDF'}
      </Button>
      {state === 'error' && error !== null ? (
        <span data-testid="download-report-error" className="font-mono text-caption text-magenta-core">
          {error}
        </span>
      ) : null}
    </div>
  );
}

/** Save a blob to disk by clicking a transient object-URL anchor. */
function triggerBrowserDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
