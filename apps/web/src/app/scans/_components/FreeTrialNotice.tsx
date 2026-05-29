import Link from 'next/link';

import { Card } from '@anthrion/ui';

import { shortWallet } from './payment-display';

/**
 * Presentational free-trial indicator (T5.4 Part 2) — pure, driven by `state`. The container
 * {@link FreeTrialBanner} loads the status from `GET /payments/free-trial` and passes it in.
 *
 * Every state is shown honestly (CLAUDE.md §4 — no silent gaps): availability, a used trial, the
 * no-wallet case (an honest call to action, not silence), plus loading and a surfaced error.
 */
export type FreeTrialNoticeState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'available'; walletAddress: string }
  | { kind: 'used'; walletAddress: string }
  | { kind: 'no-wallet' };

export function FreeTrialNotice({ state }: { state: FreeTrialNoticeState }): React.ReactElement {
  if (state.kind === 'loading') {
    return (
      <Card data-testid="free-trial-notice" data-trial-state="loading">
        <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Checking free trial…</p>
      </Card>
    );
  }

  if (state.kind === 'error') {
    return (
      <Card data-testid="free-trial-notice" data-trial-state="error">
        <p className="text-small text-text-secondary">Couldn’t check free-trial status.</p>
        <p className="mt-2 font-mono text-caption text-magenta-core">{state.message}</p>
      </Card>
    );
  }

  if (state.kind === 'no-wallet') {
    return (
      <Card data-testid="free-trial-notice" data-trial-state="no-wallet" className="flex flex-col gap-2">
        <p className="text-small font-medium text-ice">Link a wallet to use your free trial</p>
        <p className="text-small text-text-secondary">
          The one-time free trial is tied to a wallet. Link one to your account to claim it — after
          that, scans are paid per scan in USDC.
        </p>
        <Link href="/profile" className="font-mono text-caption uppercase tracking-wide text-magenta-core hover:text-magenta-light">
          Manage wallets →
        </Link>
      </Card>
    );
  }

  const wallet = shortWallet(state.walletAddress);
  if (state.kind === 'available') {
    return (
      <Card data-testid="free-trial-notice" data-trial-state="available" className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center rounded-xs border border-severity-low/40 px-2 py-0.5 font-mono text-caption uppercase tracking-wide text-severity-low">
            Free trial available
          </span>
        </div>
        <p className="text-small text-text-secondary">
          Your one-time free scan for wallet <span className="font-mono text-ice">{wallet}</span> is
          still available.
        </p>
      </Card>
    );
  }

  return (
    <Card data-testid="free-trial-notice" data-trial-state="used" className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center rounded-xs border border-trace px-2 py-0.5 font-mono text-caption uppercase tracking-wide text-text-muted">
          Free trial used
        </span>
      </div>
      <p className="text-small text-text-secondary">
        The free trial for wallet <span className="font-mono text-ice">{wallet}</span> has been used.
        Further scans are paid per scan in USDC.
      </p>
    </Card>
  );
}
