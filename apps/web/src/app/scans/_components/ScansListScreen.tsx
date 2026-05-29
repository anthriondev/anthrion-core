'use client';

import { useEffect, useState } from 'react';

import type { ScanApiClient } from '../../../lib/api-client';

import { PageShell } from './PageShell';
import { ScanList, type ScanListState } from './ScanList';

/** Container: loads the user's scans via the api client and renders {@link ScanList}. */
export function ScansListScreen({ client }: { client: ScanApiClient }): React.ReactElement {
  const [state, setState] = useState<ScanListState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await client.listScans();
      if (cancelled) {
        return;
      }
      if (result.ok) {
        setState({ kind: 'ready', scans: result.data.scans });
      } else {
        setState({ kind: 'error', message: result.error.message });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client]);

  return (
    <PageShell>
      <ScanList state={state} />
    </PageShell>
  );
}
