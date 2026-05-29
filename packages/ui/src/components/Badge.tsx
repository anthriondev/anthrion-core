import type { HTMLAttributes, ReactElement } from 'react';

import { cn } from '../cn';
import type { Severity } from '../severity';

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  severity: Severity;
}

/**
 * Severity badge (DESIGN_SYSTEM.md §2 + §7). Critical/High/Medium/Low/Info, semantic
 * colours — used ONLY in scan-result UI (reports/dashboard, T4.4), never the landing.
 * `severity` matches the `FindingSeverity` enum (T3.4); see `../severity.ts`.
 *
 * Disciplined treatment: tinted background + coloured border + coloured text, not a
 * loud filled block. Full class strings (not interpolated) so Tailwind keeps them.
 */
const severityClasses: Record<Severity, string> = {
  Critical: 'text-severity-critical border-severity-critical/40 bg-severity-critical/10',
  High: 'text-severity-high border-severity-high/40 bg-severity-high/10',
  Medium: 'text-severity-medium border-severity-medium/40 bg-severity-medium/10',
  Low: 'text-severity-low border-severity-low/40 bg-severity-low/10',
  Info: 'text-severity-info border-severity-info/40 bg-severity-info/10',
};

export function Badge({ severity, className, ...rest }: BadgeProps): ReactElement {
  return (
    <span
      data-severity={severity}
      className={cn(
        'inline-flex items-center rounded-xs border px-2 py-0.5 font-mono text-caption uppercase tracking-wide',
        severityClasses[severity],
        className,
      )}
      {...rest}
    >
      {severity}
    </span>
  );
}
