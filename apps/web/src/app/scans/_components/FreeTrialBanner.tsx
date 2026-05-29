'use client';

import { useEffect, useState } from 'react';

import type { ScanApiClient } from '../../../lib/api-client';

import { FreeTrialNotice, type FreeTrialNoticeState } from './FreeTrialNotice';

/**
 * Container for the free-trial indicator (T5.4 Part 2): loads `GET /payments/free-trial` via the
 * api client and renders {@link FreeTrialNotice}. Real data, no mock (CLAUDE.md §4). Takes the
 * client as a prop (like the other scan screens) so it stays Privy/env-free and testable.
 */
export function FreeTrialBanner({ client }: { client: ScanApiClient }): React.ReactElement {
  const [state, setState] = useState<FreeTrialNoticeState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await client.getFreeTrialStatus();
      if (cancelled) {
        return;
      }
      if (!result.ok) {
        setState({ kind: 'error', message: result.error.message });
        return;
      }
      const { status, walletAddress } = result.data;
      if (status === 'no-wallet' || walletAddress === null) {
        setState({ kind: 'no-wallet' });
        return;
      }
      setState({ kind: status, walletAddress });
    })();
    return () => {
      cancelled = true;
    };
  }, [client]);

  return <FreeTrialNotice state={state} />;
}
