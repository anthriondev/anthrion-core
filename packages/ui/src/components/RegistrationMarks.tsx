import type { ReactElement } from 'react';

import { cn } from '../cn';

export interface RegistrationMarksProps {
  /** Length of each corner arm in px. Default 12. */
  size?: number;
  /** Inset from the corner in px. Default 8. */
  inset?: number;
  className?: string;
}

/**
 * Signature "registration marks" (DESIGN_SYSTEM.md §5): thin 1px crosshair corners
 * in `trace`, low contrast — they make a layout feel measured/technical. Rendered
 * absolutely inside a `relative` parent (see {@link Card}).
 *
 * Thin, low-contrast, consistent — used only on key sections/cards, not everything.
 */
export function RegistrationMarks({
  size = 12,
  inset = 8,
  className,
}: RegistrationMarksProps): ReactElement {
  const corners = [
    { key: 'tl', style: { top: inset, left: inset, borderTopWidth: 1, borderLeftWidth: 1 } },
    { key: 'tr', style: { top: inset, right: inset, borderTopWidth: 1, borderRightWidth: 1 } },
    { key: 'bl', style: { bottom: inset, left: inset, borderBottomWidth: 1, borderLeftWidth: 1 } },
    { key: 'br', style: { bottom: inset, right: inset, borderBottomWidth: 1, borderRightWidth: 1 } },
  ] as const;

  return (
    <span aria-hidden="true" data-testid="registration-marks" className={cn('pointer-events-none', className)}>
      {corners.map((corner) => (
        <span
          key={corner.key}
          className="absolute block border-trace"
          style={{ width: size, height: size, ...corner.style }}
        />
      ))}
    </span>
  );
}
