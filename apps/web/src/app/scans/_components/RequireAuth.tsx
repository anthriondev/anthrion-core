'use client';

import { usePrivy } from '@privy-io/react-auth';
import Link from 'next/link';
import type { ReactNode } from 'react';

import { PageShell } from './PageShell';

/**
 * Client-side route protection (Sprint 1 auth pattern): render children only once Privy
 * reports an authenticated session; otherwise show an initializing / login-needed state.
 */
export function RequireAuth({ children }: { children: ReactNode }): React.ReactElement {
  const { ready, authenticated } = usePrivy();

  if (!ready) {
    return (
      <PageShell>
        <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Initializing…</p>
      </PageShell>
    );
  }

  if (!authenticated) {
    return (
      <PageShell>
        <div className="flex flex-col items-start gap-4">
          <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Not authenticated</p>
          <Link href="/" className="text-small text-magenta-core hover:text-magenta-light">
            ← Go to login
          </Link>
        </div>
      </PageShell>
    );
  }

  return <>{children}</>;
}
