import type { ScanPaymentInfo } from '@anthrion/shared/payment-api';
import { cn } from '@anthrion/ui';

import { paymentChipClasses, paymentKindLabel, paymentStatusLabel } from './payment-display';

/**
 * Payment kind/status indicator for a scan (T5.4 Part 1) — real data from the scan's `Payment`
 * record. Shown on the scan detail page next to the other scan metadata. Distinct from the
 * scan-lifecycle `ScanStatusChip` and the finding-severity `Badge`.
 *
 * For FREE_* scans the lifecycle status is always SETTLED and carries no extra meaning, so only
 * the kind label is shown. For a PAID scan the status IS meaningful (pending / settled / refund),
 * so it is appended — this becomes relevant once paid pricing is enabled; in Phase 1 (price 0)
 * every scan is FREE_PRICING and PAID is not reached.
 */
export function ScanPaymentChip({
  payment,
  className,
}: {
  payment: ScanPaymentInfo | null;
  className?: string;
}): React.ReactElement | null {
  // A scan can momentarily have no linked payment (the pre-commit window in ScanService); say so
  // honestly rather than implying a free scan.
  if (payment === null) {
    return (
      <span
        data-testid="scan-payment-chip"
        data-payment-kind="none"
        className={cn(
          'inline-flex items-center rounded-xs border px-2 py-0.5 font-mono text-caption uppercase tracking-wide',
          'border-trace text-text-muted',
          className,
        )}
      >
        No payment record
      </span>
    );
  }

  const showStatus = payment.kind === 'PAID';
  return (
    <span
      data-testid="scan-payment-chip"
      data-payment-kind={payment.kind}
      data-payment-status={payment.status}
      className={cn(
        'inline-flex items-center rounded-xs border px-2 py-0.5 font-mono text-caption uppercase tracking-wide',
        paymentChipClasses(payment.kind, payment.status),
        className,
      )}
    >
      {paymentKindLabel(payment.kind)}
      {showStatus ? ` · ${paymentStatusLabel(payment.status)}` : ''}
    </span>
  );
}
