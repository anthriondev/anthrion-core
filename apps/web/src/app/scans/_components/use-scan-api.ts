'use client';

import { usePrivy } from '@privy-io/react-auth';
import { useCallback, useMemo } from 'react';

import { createScanApiClient, type ScanApiClient } from '../../../lib/api-client';
import { clientEnv } from '../../../lib/env.client';

export interface ScanApiBundle {
  client: ScanApiClient;
  /** Privy access-token provider, passed to `consumeScanStream`. */
  getToken: () => Promise<string | null>;
  baseUrl: string;
}

/**
 * Wires the env-free T4.3b utilities to their runtime inputs at the call site
 * (DESIGN_SYSTEM/§2): base URL from `clientEnv`, token from Privy's `getAccessToken`.
 * The utilities themselves never touch Privy or env.
 */
export function useScanApi(): ScanApiBundle {
  const { getAccessToken } = usePrivy();
  const getToken = useCallback<() => Promise<string | null>>(() => getAccessToken(), [getAccessToken]);
  const baseUrl = clientEnv.NEXT_PUBLIC_API_URL;
  const client = useMemo(() => createScanApiClient({ baseUrl, getToken }), [baseUrl, getToken]);
  return { client, getToken, baseUrl };
}
