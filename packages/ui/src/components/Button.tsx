import type { ButtonHTMLAttributes, ReactElement } from 'react';

import { cn } from '../cn';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost';
export type ButtonSize = 'sm' | 'md';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Visual style (DESIGN_SYSTEM.md §7). Default `primary`. */
  variant?: ButtonVariant;
  /** Default `md`. */
  size?: ButtonSize;
}

const base =
  'inline-flex items-center justify-center rounded-card font-sans font-medium tracking-wide ' +
  'transition-colors duration-base ease-out focus-visible:outline-none focus-visible:ring-1 ' +
  'focus-visible:ring-magenta-core disabled:pointer-events-none disabled:opacity-40';

const variantClasses: Record<ButtonVariant, string> = {
  // Primary: magenta fill, dark text. Hover lightens, press deepens — subtle (§6).
  primary: 'bg-magenta-core text-void hover:bg-magenta-light active:bg-magenta-deep',
  // Secondary: outline in `trace`, ice text; border warms to magenta on hover.
  secondary: 'border border-trace bg-transparent text-ice hover:border-magenta-core hover:bg-surface',
  // Ghost: text only, faint surface on hover.
  ghost: 'bg-transparent text-ice hover:bg-surface',
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'h-9 px-4 text-caption',
  md: 'h-11 px-6 text-small',
};

export interface ButtonClassOptions {
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  // `| undefined` so a caller's optional className passes through under
  // exactOptionalPropertyTypes.
  className?: string | undefined;
}

/**
 * The Button's composed classes, exposed so a non-button element can adopt the same
 * look — e.g. a `next/link` styled as a button (which must NOT wrap a real `<button>`
 * in an `<a>`). Keeps button styling single-sourced.
 */
export function buttonClassName({ variant = 'primary', size = 'md', className }: ButtonClassOptions = {}): string {
  return cn(base, variantClasses[variant], sizeClasses[size], className);
}

/**
 * Button (DESIGN_SYSTEM.md §7): primary / secondary / ghost. Radius 8px, smooth hover.
 */
export function Button({
  variant = 'primary',
  size = 'md',
  type = 'button',
  className,
  children,
  ...rest
}: ButtonProps): ReactElement {
  return (
    <button type={type} className={buttonClassName({ variant, size, className })} {...rest}>
      {children}
    </button>
  );
}
