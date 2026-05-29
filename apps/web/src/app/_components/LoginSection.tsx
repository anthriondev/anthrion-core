'use client';

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { usePrivy } from '@privy-io/react-auth';

const POST_AUTH_DESTINATION = '/scans';

export function LoginSection(): React.ReactElement {
  const { ready, authenticated, login } = usePrivy();
  const router = useRouter();

  // Authenticated visitors do not belong on the landing page — send them to the
  // product (T-FIX.1). `replace` keeps `/` out of the back-stack so a back tap
  // from `/scans` does not loop them through the login surface again.
  useEffect(() => {
    if (ready && authenticated) {
      router.replace(POST_AUTH_DESTINATION);
    }
  }, [ready, authenticated, router]);

  if (!ready) {
    return (
      <div
        style={{
          color: 'var(--color-ice)',
          opacity: 0.4,
          fontSize: '0.75rem',
          letterSpacing: '0.1em',
        }}
      >
        INITIALIZING
      </div>
    );
  }

  if (authenticated) {
    return (
      <div
        style={{
          color: 'var(--color-ice)',
          opacity: 0.4,
          fontSize: '0.75rem',
          letterSpacing: '0.1em',
        }}
      >
        REDIRECTING
      </div>
    );
  }

  return (
    <button
      onClick={login}
      style={{
        background: 'var(--color-magenta-core)',
        border: 'none',
        color: '#ffffff',
        padding: '10px 32px',
        fontSize: '0.75rem',
        fontWeight: 600,
        letterSpacing: '0.15em',
        cursor: 'pointer',
      }}
    >
      CONNECT
    </button>
  );
}
