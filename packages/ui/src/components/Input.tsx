import type { InputHTMLAttributes, ReactElement, ReactNode } from 'react';

import { cn } from '../cn';

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

/**
 * Input (DESIGN_SYSTEM.md §7): `surface` background, `trace` border; on focus the
 * border becomes `magenta-core` — a border change, NOT a glow.
 */
export function Input({ className, type = 'text', ...rest }: InputProps): ReactElement {
  return (
    <input
      type={type}
      className={cn(
        'w-full rounded-card border border-trace bg-surface px-4 py-2.5 font-sans text-body text-ice',
        'placeholder:text-text-muted transition-colors duration-fast ease-out',
        'focus:border-magenta-core focus:outline-none',
        'disabled:cursor-not-allowed disabled:opacity-40',
        className,
      )}
      {...rest}
    />
  );
}

export interface FieldProps {
  /** Field label — rendered as an uppercase mono caption. */
  label: string;
  htmlFor?: string;
  // `| undefined` so callers can pass a possibly-absent value directly under
  // exactOptionalPropertyTypes (e.g. `error={errors.foo}`).
  /** Helper text under the control. */
  hint?: string | undefined;
  /** Error message; when set it replaces the hint and tints magenta. */
  error?: string | undefined;
  className?: string | undefined;
  children: ReactNode;
}

/**
 * Field: composable label + control + hint/error wrapper. Pair with {@link Input}.
 */
export function Field({ label, htmlFor, hint, error, className, children }: FieldProps): ReactElement {
  return (
    <div className={cn('flex flex-col gap-2', className)}>
      <label htmlFor={htmlFor} className="font-mono text-caption uppercase text-text-muted">
        {label}
      </label>
      {children}
      {error !== undefined ? (
        <p className="font-mono text-caption text-magenta-core">{error}</p>
      ) : hint !== undefined ? (
        <p className="text-small text-text-secondary">{hint}</p>
      ) : null}
    </div>
  );
}
