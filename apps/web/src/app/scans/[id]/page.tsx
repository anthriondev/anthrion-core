'use client';

import { useParams } from 'next/navigation';

import { RequireAuth } from '../_components/RequireAuth';
import { ScanDetailScreen } from '../_components/ScanDetailScreen';
import { useScanApi } from '../_components/use-scan-api';

export default function ScanDetailPage(): React.ReactElement {
  const params = useParams<{ id: string }>();
  const { client, getToken, baseUrl } = useScanApi();
  return (
    <RequireAuth>
      <ScanDetailScreen scanId={params.id} client={client} getToken={getToken} baseUrl={baseUrl} />
    </RequireAuth>
  );
}
