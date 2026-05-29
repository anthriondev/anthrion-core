import type { FindingResponse } from '@anthrion/shared/scan-api';
import { Card } from '@anthrion/ui';

import { FindingCard } from './FindingCard';
import { SeveritySummary } from './SeveritySummary';
import { countBySeverity, sortFindings } from './findings';

/**
 * Findings report section (T4.4) — shown on `/scans/[id]` once the scan is DONE,
 * replacing the T4.3c results placeholder. Severity summary → findings sorted
 * most-severe first → each a Card with collapsible evidence.
 */
export function FindingsSection({ findings }: { findings: FindingResponse[] }): React.ReactElement {
  if (findings.length === 0) {
    return (
      <Card withMarks data-testid="findings-empty">
        <div className="flex flex-col gap-2 py-4">
          <h2 className="text-h3 text-ice">Scan complete — no findings</h2>
          <p className="max-w-prose text-small text-text-secondary">
            No vulnerabilities were detected in the scope that was tested. This is not a guarantee
            that the target is secure — it means the checks that ran did not surface an issue.
          </p>
        </div>
      </Card>
    );
  }

  const sorted = sortFindings(findings);

  return (
    <section data-testid="findings-section" className="flex flex-col gap-6">
      <div className="flex flex-col gap-3">
        <h2 className="text-h3 text-ice">Findings</h2>
        <SeveritySummary counts={countBySeverity(findings)} />
      </div>
      <div className="flex flex-col gap-4">
        {sorted.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>
    </section>
  );
}
