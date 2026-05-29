'use client';

import { PrivyProvider } from '@privy-io/react-auth';

import { clientEnv } from '../lib/env.client';

export function Providers({ children }: { children: React.ReactNode }): React.ReactElement {
  return (
    <PrivyProvider
      appId={clientEnv.NEXT_PUBLIC_PRIVY_APP_ID}
      config={{
        loginMethods: ['email', 'wallet'],
        appearance: {
          theme: 'dark',
          accentColor: '#E0218A',
        },
      }}
    >
      {children}
    </PrivyProvider>
  );
}
