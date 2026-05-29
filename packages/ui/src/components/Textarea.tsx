import type { TextareaHTMLAttributes, ReactElement } from 'react';

import { cn } from '../cn';

export type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;

/**
 * Multi-line text input — the textarea sibling of {@link Input}, same surface/trace
 * treatment and magenta focus border (not a glow). For longer input like a pasted
 * system prompt.
 */
export function Textarea({ className, rows = 4, ...rest }: TextareaProps): ReactElement {
  return (
    <textarea
      rows={rows}
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
