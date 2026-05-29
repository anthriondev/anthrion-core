import type { ReactNode } from 'react';

import { cn } from '@anthrion/ui';

/** Consistent dark page container for the scan screens (DESIGN_SYSTEM.md spacing/§4). */
export function PageShell({ children, className }: { children: ReactNode; className?: string }): React.ReactElement {
  return (
    <main className="min-h-screen bg-void text-ice">
      <div className={cn('mx-auto w-full max-w-5xl px-6 py-12 sm:py-16', className)}>{children}</div>
    </main>
  );
}
