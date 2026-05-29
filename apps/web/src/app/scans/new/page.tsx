'use client';

import { useRouter } from 'next/navigation';

import { FreeTrialBanner } from '../_components/FreeTrialBanner';
import { NewScanScreen } from '../_components/NewScanScreen';
import { RequireAuth } from '../_components/RequireAuth';
import { useScanApi } from '../_components/use-scan-api';

export default function NewScanPage(): React.ReactElement {
  const { client } = useScanApi();
  const router = useRouter();
  return (
    <RequireAuth>
      <NewScanScreen
        client={client}
        push={(href) => router.push(href)}
        // Free-trial availability indicator (T5.4 Part 2) shown above the form.
        beforeForm={<FreeTrialBanner client={client} />}
      />
    </RequireAuth>
  );
}
