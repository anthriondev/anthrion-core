/**
 * Severity levels for the {@link Badge} component.
 *
 * These mirror the `FindingSeverity` enum in `@anthrion/scan-engine`
 * (severity.ts, T3.4): Critical/High/Medium/Low/Info. We re-declare the union here
 * rather than import it because `scan-engine` pulls Playwright as a dependency, and
 * `packages/ui` must stay light (the same reason `@anthrion/shared` keeps wire types
 * independent). `severity.test.ts` documents the intended 1:1 correspondence.
 */
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;

export type Severity = (typeof SEVERITIES)[number];
