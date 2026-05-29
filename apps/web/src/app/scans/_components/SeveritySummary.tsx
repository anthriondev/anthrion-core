import { Badge, cn, SEVERITIES } from '@anthrion/ui';

import type { SeverityCounts } from './findings';

/**
 * Quick severity overview strip: count per severity (most-severe first), using the
 * same semantic colours as `Badge`. Zero-count levels are de-emphasised so the full
 * picture is visible at a glance without shouting clean levels.
 */
export function SeveritySummary({ counts }: { counts: SeverityCounts }): React.ReactElement {
  const total = SEVERITIES.reduce((sum, severity) => sum + counts[severity], 0);

  return (
    <div data-testid="severity-summary" className="flex flex-wrap items-center gap-4">
      <span className="font-mono text-caption uppercase tracking-wide text-text-muted">
        {total} finding{total === 1 ? '' : 's'}
      </span>
      {SEVERITIES.map((severity) => (
        <div key={severity} className={cn('flex items-center gap-2', counts[severity] === 0 ? 'opacity-40' : '')}>
          <span data-testid={`count-${severity}`} className="text-small tabular-nums text-ice">
            {counts[severity]}
          </span>
          <Badge severity={severity} />
        </div>
      ))}
    </div>
  );
}
