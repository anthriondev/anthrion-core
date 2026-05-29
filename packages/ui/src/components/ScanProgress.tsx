import type { ReactElement } from 'react';

import type {
  ScanStreamEvent,
  ScanStreamLifecycleEvent,
  ScanStreamStageEvent,
} from '@anthrion/shared';

import { cn } from '../cn';

import { Mark } from './Mark';

type LifecycleStatus = ScanStreamLifecycleEvent['status'];
type StagePhase = ScanStreamStageEvent['phase'];

export interface ScanProgressProps {
  /**
   * The ordered scan-progress event log. This is the cross-app SSE/Redis contract
   * from `@anthrion/shared` (T4.2): `stage` events (engine phases) and `lifecycle`
   * events (QUEUED → RUNNING → DONE/FAILED).
   *
   * BOUNDARY (T4.3a): this component is a SHELL — it renders whatever events it is
   * GIVEN. It does NOT open the SSE connection. Subscribing to
   * `GET /scans/:id/stream` and feeding events here is T4.3c.
   */
  events: ScanStreamEvent[];
  /**
   * Current lifecycle status. If omitted it is derived from the last `lifecycle`
   * event in `events`. Drives the live (spinning mark + pulse) state.
   */
  status?: LifecycleStatus;
  className?: string;
}

const phaseLabels: Record<StagePhase, string> = {
  'layer-1': 'Layer 1 · Static probes',
  'layer-2': 'Layer 2 · Adaptive attacker',
  'layer-2-category': 'Layer 2 · Category',
  'web-load': 'Web · Page load',
  'web-probes': 'Web · DAST probes',
  'api-scan': 'API · Probes',
  'web3-l1': 'Web3 · Wallet interaction',
  'web3-l3': 'Web3 · On-chain context',
  'web3-l2': 'Web3 · Frontend & infrastructure',
};

const statusChipClasses: Record<LifecycleStatus, string> = {
  QUEUED: 'border-trace text-text-secondary',
  RUNNING: 'border-magenta-core/40 text-magenta-core',
  DONE: 'border-severity-low/40 text-severity-low',
  FAILED: 'border-severity-critical/40 text-severity-critical',
};

function lastLifecycleStatus(events: ScanStreamEvent[]): LifecycleStatus | undefined {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i];
    if (event !== undefined && event.type === 'lifecycle') {
      return event.status;
    }
  }
  return undefined;
}

function eventLines(event: ScanStreamEvent): { primary: string; secondary: string } {
  if (event.type === 'stage') {
    return {
      primary: event.message,
      secondary: `${phaseLabels[event.phase]} · ${event.status}`,
    };
  }
  return {
    primary: event.message ?? `Scan ${event.status.toLowerCase()}`,
    secondary: event.status,
  };
}

/** Is this row still in-flight (a started stage, or queued/running lifecycle)? */
function isPending(event: ScanStreamEvent): boolean {
  if (event.type === 'stage') {
    return event.status === 'started';
  }
  return event.status === 'QUEUED' || event.status === 'RUNNING';
}

/** Did this row fail? */
function isFailure(event: ScanStreamEvent): boolean {
  return event.type === 'lifecycle' && event.status === 'FAILED';
}

/**
 * Scan-progress (DESIGN_SYSTEM.md §7): the running list of steps with a live "alive"
 * indicator — the legitimate place for the rotating mark (§6). Shell only; see the
 * `events` prop note for the T4.3c boundary.
 */
export function ScanProgress({ events, status, className }: ScanProgressProps): ReactElement {
  const resolvedStatus: LifecycleStatus = status ?? lastLifecycleStatus(events) ?? 'QUEUED';
  const isRunning = resolvedStatus === 'RUNNING';
  const lastIndex = events.length - 1;

  return (
    <section
      data-testid="scan-progress"
      data-status={resolvedStatus}
      className={cn('relative rounded-panel border border-trace bg-surface p-6', className)}
    >
      <header className="mb-6 flex items-center gap-3">
        <Mark size={28} spinning={isRunning} />
        <span className="font-mono text-caption uppercase text-text-muted">Scan progress</span>
        <span
          data-testid="scan-status"
          className={cn(
            'ml-auto inline-flex items-center gap-2 rounded-xs border px-2 py-0.5 font-mono text-caption uppercase',
            statusChipClasses[resolvedStatus],
          )}
        >
          {isRunning ? (
            <span className="h-1.5 w-1.5 rounded-full bg-magenta-core animate-live-pulse motion-reduce:animate-none" />
          ) : null}
          {resolvedStatus}
        </span>
      </header>

      {events.length === 0 ? (
        <p className="text-small text-text-muted">Waiting for scan events…</p>
      ) : (
        <ol className="flex flex-col gap-4">
          {events.map((event, index) => {
            const { primary, secondary } = eventLines(event);
            const live = isRunning && index === lastIndex && isPending(event);
            const failed = isFailure(event);
            return (
              <li key={index} className="flex items-start gap-3">
                <span
                  aria-hidden="true"
                  className={cn(
                    'mt-1.5 h-2 w-2 shrink-0 rounded-full',
                    failed
                      ? 'bg-severity-critical'
                      : isPending(event)
                        ? cn('border border-magenta-core/70', live && 'animate-live-pulse motion-reduce:animate-none')
                        : 'bg-magenta-core',
                  )}
                />
                <div className="flex flex-col gap-0.5">
                  <span className="text-small text-ice">{primary}</span>
                  <span className="font-mono text-caption uppercase text-text-muted">{secondary}</span>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
