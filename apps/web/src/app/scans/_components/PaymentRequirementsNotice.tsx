import type { PaymentRequiredResponse } from '@anthrion/shared/x402';
import { Card } from '@anthrion/ui';

import { formatUsdcAtomic, networkLabel } from './payment-display';

/**
 * HONEST x402 scaffold (T5.4 Part 3) — NOT a working pay button.
 *
 * Rendered when `POST /scans` answers 402 with `PaymentRequirements` (the x402 contract from
 * T5.2). It shows, truthfully, what a paid scan would cost (amount / network / asset), and states
 * plainly that paid scans are NOT active yet in this phase. There is deliberately NO pay action:
 * the wallet-transaction flow (connecting a wallet, signing the EIP-3009 authorization, sending
 * `X-PAYMENT`, handling settle) is the facilitator boundary and is not implemented here — the same
 * honest boundary the backend marks with `NotConfiguredFacilitatorClient` / a 503.
 *
 * In Phase 1 the global price is 0, so normal users never reach this (they get a free scan, 201).
 * The structure is in place so a real pay flow can slot in here once a facilitator + treasury
 * wallet are wired — without reworking the screen. The marker below is intentional and explicit.
 *
 * BOUNDARY (facilitator pending): do NOT add wallet connect / X-PAYMENT signing / settle handling
 * to this component without the facilitator + treasury key package — see the backend payment layer.
 */
export function PaymentRequirementsNotice({
  paymentRequired,
}: {
  paymentRequired: PaymentRequiredResponse;
}): React.ReactElement {
  const options = paymentRequired.accepts;

  return (
    <Card withMarks data-testid="payment-requirements-notice" className="flex flex-col gap-4 border-magenta-core/30">
      <div className="flex flex-col gap-1">
        <span className="font-mono text-caption uppercase tracking-wide text-magenta-core">
          Paid scans not active yet
        </span>
        <p className="text-small text-text-secondary">
          During the promotional period scans are free. Paid scans (USDC, pay-per-scan) will be
          enabled later; the cost a scan would carry is shown below for transparency. You can’t be
          charged from here yet — there is no payment step.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <span className="font-mono text-caption uppercase tracking-wide text-text-muted">
          {paymentRequired.error ?? 'Payment required'}
        </span>
        <ul className="flex flex-col gap-2">
          {options.map((option, index) => (
            <li
              key={`${option.network}-${option.asset}-${index}`}
              data-testid="payment-option"
              className="flex flex-col gap-1 rounded-xs border border-trace bg-void p-3"
            >
              <span className="text-small text-ice">
                {formatUsdcAtomic(option.maxAmountRequired)} on {networkLabel(option.network)}
              </span>
              <span className="break-all font-mono text-caption text-text-muted">
                Pay to {option.payTo} · asset {option.asset}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <p className="font-mono text-caption text-text-muted">
        Awaiting payment facilitator — the on-chain payment flow is not wired in this phase.
      </p>
    </Card>
  );
}
