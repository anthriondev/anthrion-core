'use client';

import { RequireAuth } from './_components/RequireAuth';
import { ScansListScreen } from './_components/ScansListScreen';
import { useScanApi } from './_components/use-scan-api';

export default function ScansPage(): React.ReactElement {
  const { client } = useScanApi();
  return (
    <RequireAuth>
      <ScansListScreen client={client} />
    </RequireAuth>
  );
}
