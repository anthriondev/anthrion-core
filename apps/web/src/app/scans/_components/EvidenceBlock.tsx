'use client';

import { useState } from 'react';

import { Button, CodeBlock } from '@anthrion/ui';
import type { FindingResponse } from '@anthrion/shared/scan-api';

export interface EvidenceBlockProps {
  evidence: FindingResponse['evidence'];
}

/**
 * Collapsible evidence for a finding (DESIGN_SYSTEM.md §7 CodeBlock). Evidence can be
 * long (attack payloads, raw LLM output), so it is collapsed by DEFAULT — the content
 * is not rendered until expanded, keeping the report from becoming a wall of text.
 */
export function EvidenceBlock({ evidence }: EvidenceBlockProps): React.ReactElement {
  const [open, setOpen] = useState(false);

  const hasMetadata = evidence.metadata !== undefined && Object.keys(evidence.metadata).length > 0;
  const metadataText = hasMetadata ? JSON.stringify(evidence.metadata, null, 2) : null;

  return (
    <div className="flex flex-col gap-3">
      <Button
        variant="ghost"
        size="sm"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
        className="self-start"
      >
        {open ? 'Hide evidence' : 'Show evidence'}
      </Button>
      {open ? (
        <div data-testid="evidence-content" className="flex flex-col gap-3">
          <CodeBlock label="Input" code={evidence.input} />
          <CodeBlock label="Output" code={evidence.output} />
          {metadataText !== null ? <CodeBlock label="Metadata" code={metadataText} /> : null}
        </div>
      ) : null}
    </div>
  );
}
