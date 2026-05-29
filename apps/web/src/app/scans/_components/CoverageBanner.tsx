import type { ReportCoverage } from '@anthrion/shared/scan-api';
import { Card } from '@anthrion/ui';

/**
 * Coverage banner for `/scans/[id]` (T6.2) — surfaces partial / incomplete coverage in
 * the SAME terms the PDF uses, so the UI and the PDF never disagree about whether a
 * scan's coverage was complete (CLAUDE.md §3 honesty).
 *
 * The banner reads the `reportCoverage` value the worker persisted at PDF-generation
 * time. The shape lives in `@anthrion/shared/scan-api` (T6.2 — single source of truth).
 *
 * Three states:
 *   - `coverage === null`               — UNKNOWN (FAILED scans, scans whose report
 *                                         never generated, pre-T6.2 rows). Renders
 *                                         NOTHING — never a claim of completeness.
 *   - `coverage.complete === true`      — renders nothing (no celebration).
 *   - `coverage.complete === false`     — renders one block per gap, with the same
 *                                         per-type title + detail the PDF carries.
 */
export interface CoverageBannerProps {
  coverage: ReportCoverage | null;
}

export function CoverageBanner({ coverage }: CoverageBannerProps): React.ReactElement | null {
  if (coverage === null || coverage.complete) {
    return null;
  }

  return (
    <section
      data-testid="coverage-banner"
      data-coverage-state="incomplete"
      className="flex flex-col gap-3"
    >
      <p className="font-mono text-caption uppercase tracking-wide text-text-muted">Coverage — incomplete</p>
      <div className="flex flex-col gap-2">
        {coverage.gaps.map((gap) => (
          <Card
            key={gap.kind}
            data-testid="coverage-gap"
            data-coverage-gap-kind={gap.kind}
            className="border-l-2 border-l-severity-medium/80"
          >
            <p className="text-body font-medium text-severity-medium">{gap.title}</p>
            <p className="mt-1 text-small text-text-secondary">{gap.detail}</p>
          </Card>
        ))}
      </div>
    </section>
  );
}
