'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { usePrivy } from '@privy-io/react-auth';
import { z } from 'zod';

import { clientEnv } from '../../lib/env.client';

const walletSchema = z.object({
  address: z.string(),
  chain: z.enum(['EVM', 'SOLANA']),
});

const profileSchema = z.object({
  id: z.string(),
  privyUserId: z.string(),
  email: z.string().nullable(),
  createdAt: z.string(),
  wallets: z.array(walletSchema),
});

type Profile = z.infer<typeof profileSchema>;

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-GB', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function ChainBadge({ chain }: { chain: 'EVM' | 'SOLANA' }): React.ReactElement {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        border: '1px solid var(--color-trace)',
        fontSize: '0.65rem',
        letterSpacing: '0.12em',
        color: chain === 'EVM' ? 'var(--color-magenta-light)' : 'var(--color-ice)',
        opacity: chain === 'EVM' ? 1 : 0.7,
        fontFamily: 'monospace',
      }}
    >
      {chain}
    </span>
  );
}

function ProfileCard({ profile, onLogout }: { profile: Profile; onLogout: () => void }): React.ReactElement {
  return (
    <div
      style={{
        background: 'var(--color-surface)',
        border: '1px solid var(--color-trace)',
        // Responsive padding (DESIGN_SYSTEM.md §8): 24px on mobile, scaling up
        // to 40px on desktop. The card was hard-coded to 40px which left only
        // ~310px of usable width at 390px, squeezing wallet rows.
        padding: 'clamp(24px, 4vw, 40px)',
        maxWidth: '560px',
        width: '100%',
        position: 'relative',
      }}
    >
      {/* registration marks — design system §5 */}
      <span style={{ position: 'absolute', top: 8, left: 8, width: 12, height: 12, borderTop: '1px solid var(--color-trace)', borderLeft: '1px solid var(--color-trace)' }} />
      <span style={{ position: 'absolute', top: 8, right: 8, width: 12, height: 12, borderTop: '1px solid var(--color-trace)', borderRight: '1px solid var(--color-trace)' }} />
      <span style={{ position: 'absolute', bottom: 8, left: 8, width: 12, height: 12, borderBottom: '1px solid var(--color-trace)', borderLeft: '1px solid var(--color-trace)' }} />
      <span style={{ position: 'absolute', bottom: 8, right: 8, width: 12, height: 12, borderBottom: '1px solid var(--color-trace)', borderRight: '1px solid var(--color-trace)' }} />

      <p style={{ fontSize: '0.65rem', letterSpacing: '0.15em', color: 'var(--color-magenta-core)', marginBottom: 24 }}>
        ACCOUNT
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <Row label="EMAIL" value={profile.email ?? '—'} />
        <Row label="PRIVY ID" value={profile.privyUserId} mono />
        <Row label="JOINED" value={formatDate(profile.createdAt)} />

        <div>
          <p style={{ fontSize: '0.65rem', letterSpacing: '0.12em', color: 'var(--color-ice)', opacity: 0.38, marginBottom: 12 }}>
            WALLETS
          </p>
          {profile.wallets.length === 0 ? (
            <p style={{ fontSize: '0.875rem', color: 'var(--color-ice)', opacity: 0.4 }}>—</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {profile.wallets.map((w) => (
                <div key={w.address} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <ChainBadge chain={w.chain} />
                  <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--color-ice)', opacity: 0.7, wordBreak: 'break-all' }}>
                    {w.address}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ marginTop: 40, display: 'flex', gap: 12 }}>
        <Link
          href="/"
          style={{
            fontSize: '0.7rem',
            letterSpacing: '0.12em',
            color: 'var(--color-ice)',
            opacity: 0.5,
            textDecoration: 'none',
            padding: '8px 0',
          }}
        >
          ← HOME
        </Link>
        <button
          onClick={onLogout}
          style={{
            marginLeft: 'auto',
            background: 'transparent',
            border: '1px solid var(--color-magenta-core)',
            color: 'var(--color-magenta-core)',
            padding: '8px 24px',
            fontSize: '0.7rem',
            letterSpacing: '0.15em',
            cursor: 'pointer',
          }}
        >
          LOGOUT
        </button>
      </div>
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }): React.ReactElement {
  return (
    <div>
      <p style={{ fontSize: '0.65rem', letterSpacing: '0.12em', color: 'var(--color-ice)', opacity: 0.38, marginBottom: 4 }}>
        {label}
      </p>
      <p style={{ fontSize: '0.875rem', color: 'var(--color-ice)', fontFamily: mono ? 'monospace' : undefined, wordBreak: 'break-all' }}>
        {value}
      </p>
    </div>
  );
}

export default function ProfilePage(): React.ReactElement {
  const { ready, authenticated, getAccessToken, logout } = usePrivy();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!ready || !authenticated) return;

    void (async () => {
      try {
        const token = await getAccessToken();
        if (token === null) {
          setError('Could not retrieve access token');
          return;
        }

        const res = await fetch(`${clientEnv.NEXT_PUBLIC_API_URL}/users/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!res.ok) {
          setError(`API error: ${res.status}`);
          return;
        }

        const raw: unknown = await res.json();
        const parsed = profileSchema.safeParse(raw);

        if (!parsed.success) {
          setError('Unexpected response shape from API');
          return;
        }

        setProfile(parsed.data);
      } catch (cause) {
        // Surface the underlying cause to the console so a network / fetch failure is
        // observable (CLAUDE.md §3 — never swallow). The UI still shows a friendly message.
        console.error('Failed to load profile:', cause);
        setError('Failed to load profile');
      }
    })();
  }, [ready, authenticated, getAccessToken]);

  const handleLogout = (): void => {
    void logout();
  };

  if (!ready) {
    return (
      <main style={centeredMain}>
        <p style={mutedCaption}>INITIALIZING</p>
      </main>
    );
  }

  if (!authenticated) {
    return (
      <main style={centeredMain}>
        <p style={{ ...mutedCaption, marginBottom: 24 }}>NOT AUTHENTICATED</p>
        <Link
          href="/"
          style={{
            fontSize: '0.7rem',
            letterSpacing: '0.15em',
            color: 'var(--color-magenta-core)',
            textDecoration: 'none',
          }}
        >
          ← GO TO LOGIN
        </Link>
      </main>
    );
  }

  if (error !== null) {
    return (
      <main style={centeredMain}>
        <p style={{ color: 'var(--color-magenta-core)', fontSize: '0.75rem', letterSpacing: '0.1em' }}>{error}</p>
      </main>
    );
  }

  if (profile === null) {
    return (
      <main style={centeredMain}>
        <p style={mutedCaption}>LOADING PROFILE</p>
      </main>
    );
  }

  return (
    <main style={centeredMain}>
      <ProfileCard profile={profile} onLogout={handleLogout} />
    </main>
  );
}

const centeredMain: React.CSSProperties = {
  minHeight: '100vh',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  flexDirection: 'column',
  padding: '32px 16px',
};

const mutedCaption: React.CSSProperties = {
  fontSize: '0.65rem',
  letterSpacing: '0.15em',
  color: 'var(--color-ice)',
  opacity: 0.38,
};
