import type { HTMLAttributes, ReactElement } from 'react';

import { cn } from '../cn';

export interface CodeBlockProps extends HTMLAttributes<HTMLPreElement> {
  /** Code/text to render. Alternatively pass `children`. */
  code?: string;
  /** Optional caption above the block (e.g. "PROMPT", "PAYLOAD", scan ID). */
  label?: string;
}

/**
 * Code / mono block (DESIGN_SYSTEM.md §7): JetBrains Mono on a `void` background
 * (darker than `surface`), for prompts, payloads and scan IDs.
 */
export function CodeBlock({ code, label, className, children, ...rest }: CodeBlockProps): ReactElement {
  return (
    <div className="flex flex-col gap-2">
      {label !== undefined ? (
        <span className="font-mono text-caption uppercase text-text-muted">{label}</span>
      ) : null}
      <pre
        className={cn(
          'overflow-x-auto rounded-card border border-trace bg-void p-4',
          'font-mono text-small leading-relaxed text-ice',
          className,
        )}
        {...rest}
      >
        <code>{code ?? children}</code>
      </pre>
    </div>
  );
}
