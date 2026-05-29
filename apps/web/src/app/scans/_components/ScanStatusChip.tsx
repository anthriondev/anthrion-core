import type { ScanStatusWire } from '@anthrion/shared/scan-api';
import { cn } from '@anthrion/ui';

/**
 * Scan lifecycle status indicator (QUEUED/RUNNING/DONE/FAILED). This is the SCAN's
 * status — distinct from a finding's severity Badge (T4.4). Mirrors the status chip in
 * the `ScanProgress` header for visual consistency.
 */
const statusChipClasses: Record<ScanStatusWire, string> = {
  QUEUED: 'border-trace text-text-secondary',
  RUNNING: 'border-magenta-core/40 text-magenta-core',
  DONE: 'border-severity-low/40 text-severity-low',
  FAILED: 'border-severity-critical/40 text-severity-critical',
};

export function ScanStatusChip({ status, className }: { status: ScanStatusWire; className?: string }): React.ReactElement {
  return (
    <span
      data-status={status}
      className={cn(
        'inline-flex items-center rounded-xs border px-2 py-0.5 font-mono text-caption uppercase tracking-wide',
        statusChipClasses[status],
        className,
      )}
    >
      {status}
    </span>
  );
}
