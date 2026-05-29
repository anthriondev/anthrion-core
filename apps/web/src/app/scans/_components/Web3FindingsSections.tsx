import type { FindingResponse } from '@anthrion/shared/scan-api';
import { Card } from '@anthrion/ui';

import { FindingCard } from './FindingCard';
import { SeveritySummary } from './SeveritySummary';
import { countBySeverity, partitionWeb3Findings, sortFindings } from './findings';

/**
 * Web3 dApp scan findings — three sections (L1 wallet / L2 frontend / L3
 * on-chain) per the T-A3.8 spec. Each section renders its own findings list
 * + severity summary so the report reads as three distinct concerns rather
 * than one undifferentiated list.
 *
 * An empty section renders an honest "no findings detected at this layer"
 * note rather than vanishing — silence at a layer is meaningful (it tells the
 * reader that layer ran cleanly), and the coverage banner above already
 * carries any per-layer incompleteness.
 *
 * Unknown-category findings (none expected on a real web3-dapp scan, but the
 * partition tolerates them) collapse into a generic "Other" section so they
 * are never dropped silently.
 */
export function Web3FindingsSections({ findings }: { findings: FindingResponse[] }): React.ReactElement {
  const partition = partitionWeb3Findings(findings);
  return (
    <section data-testid="web3-findings-sections" className="flex flex-col gap-8">
      <Web3LayerSection
        testId="web3-l1-section"
        title="L1 — Wallet interaction"
        subtitle="Findings from the synthetic EIP-1193 capture: approval phishing, typed-data signature smell, EIP-7702 SetCode, Permit2 mass approval, chain-id mismatch."
        findings={partition.l1}
      />
      <Web3LayerSection
        testId="web3-l2-section"
        title="L2 — Frontend & infrastructure"
        subtitle="Findings from the loaded page surface: SRI absence on cross-origin scripts, pinned-CDN bundle-drift, known-bad domain references, TLS / DNS hygiene."
        findings={partition.l2}
      />
      <Web3LayerSection
        testId="web3-l3-section"
        title="L3 — On-chain context"
        subtitle="Findings from the read-only RPC + explorer cross-checks: unverified source, opaque proxy implementation, EOA admin, fresh deployment, token impersonation. Aggregate `elevated-risk-contract` finding appears here when ≥2 indicators hit one contract."
        findings={partition.l3}
      />
      {partition.unknown.length > 0 ? (
        <Web3LayerSection
          testId="web3-other-section"
          title="Other"
          subtitle="Findings whose category is not part of the Web3 L1 / L2 / L3 taxonomy."
          findings={partition.unknown}
        />
      ) : null}
    </section>
  );
}

interface Web3LayerSectionProps {
  testId: string;
  title: string;
  subtitle: string;
  findings: FindingResponse[];
}

function Web3LayerSection({ testId, title, subtitle, findings }: Web3LayerSectionProps): React.ReactElement {
  if (findings.length === 0) {
    return (
      <section data-testid={testId} className="flex flex-col gap-3">
        <header className="flex flex-col gap-1">
          <h2 className="text-h3 text-ice">{title}</h2>
          <p className="max-w-prose text-small text-text-secondary">{subtitle}</p>
        </header>
        <Card data-testid={`${testId}-empty`}>
          <div className="flex flex-col gap-2 py-2">
            <p className="font-mono text-caption uppercase tracking-wide text-text-muted">
              No findings at this layer
            </p>
            <p className="text-small text-text-secondary">
              No indicators surfaced from this layer's checks. See the coverage notes above for any
              sub-check that was honestly skipped or could not be completed.
            </p>
          </div>
        </Card>
      </section>
    );
  }
  const sorted = sortFindings(findings);
  return (
    <section data-testid={testId} className="flex flex-col gap-3">
      <header className="flex flex-col gap-1">
        <h2 className="text-h3 text-ice">
          {title} ({findings.length})
        </h2>
        <p className="max-w-prose text-small text-text-secondary">{subtitle}</p>
      </header>
      <SeveritySummary counts={countBySeverity(findings)} />
      <div className="flex flex-col gap-4">
        {sorted.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </section>
  );
}
