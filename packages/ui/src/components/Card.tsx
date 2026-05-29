import type { HTMLAttributes, ReactElement } from 'react';

import { cn } from '../cn';

import { RegistrationMarks } from './RegistrationMarks';

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /** Render registration marks in the corners (DESIGN_SYSTEM.md §5). Default false. */
  withMarks?: boolean;
}

/**
 * Card (DESIGN_SYSTEM.md §7): `surface` background, 1px `trace` border, 8px radius.
 * Optional registration marks in the corners for key cards.
 */
export function Card({ withMarks = false, className, children, ...rest }: CardProps): ReactElement {
  return (
    <div
      className={cn('relative rounded-card border border-trace bg-surface p-6', className)}
      {...rest}
    >
      {withMarks ? <RegistrationMarks /> : null}
      {children}
    </div>
  );
}
