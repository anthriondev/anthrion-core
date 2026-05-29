import type { FindingResponse } from '@anthrion/shared/scan-api';
import { Badge, Card } from '@anthrion/ui';

import { EvidenceBlock } from './EvidenceBlock';
import { toBadgeSeverity } from './findings';

/** One finding rendered as a Card (T4.3a): title + severity Badge + category, then
 * description, recommendation, and collapsible evidence. */
export function FindingCard({ finding }: { finding: FindingResponse }): React.ReactElement {
  return (
    <Card data-testid="finding-card" className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <h3 className="text-h3 text-ice">{finding.title}</h3>
        <Badge severity={toBadgeSeverity(finding.severity)} />
      </div>

      <p className="font-mono text-caption uppercase tracking-wide text-text-muted">{finding.category}</p>

      <p className="max-w-prose text-small text-text-secondary">{finding.description}</p>

      <div className="flex flex-col gap-1">
        <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Recommendation</p>
        <p className="max-w-prose text-small text-ice">{finding.recommendation}</p>
      </div>

      <EvidenceBlock evidence={finding.evidence} />
    </Card>
  );
}
