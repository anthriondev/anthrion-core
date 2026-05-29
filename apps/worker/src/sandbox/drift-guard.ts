import { scanTypeSchema } from '@anthrion/scan-engine';
import type { SandboxJob } from '@anthrion/sandbox-runtime';

import type { ScanSandbox } from './manager';

/**
 * T-FIX.9: sandbox-image-vs-source schema drift guard.
 *
 * The incident: in T-A1.3 follow-up an `api-scan` job failed in production because
 * the running `anthrion-scan-runtime:latest` image had been built before Sprint A1
 * and still carried the 2-element `scanTypeSchema`. The image was happy; the worker
 * was happy; only the live scan tripped — far too late.
 *
 * Decision (PROCEED under EXECUTION-PLAYBOOK.md §4 v2 — clear, reversible):
 * the HARD guard runs at worker startup, not at first live use. The sandbox
 * `selftest` op now reports the schema baked into the IMAGE (see
 * `packages/sandbox-runtime/src/run.ts` → `contract.scanTypes`); we compare it to
 * the WORKER'S source-of-truth `scanTypeSchema.options`. Mismatch ⇒ refuse to
 * accept jobs, with an actionable message pointing at the rebuild script.
 *
 * Why hard (option 2) over soft build-time (option 1): both are mechanically
 * reasonable, but a soft check at `pnpm build` does not help an operator who
 * pulled a stale image and just runs the worker — exactly the production case
 * that bit us. The hard guard fails CLOSED (no jobs ever accepted), which is the
 * safe direction for a security product. The optional build-time soft check
 * remains worth adding in a follow-up sprint but is not required to close
 * T-FIX.9.
 */

export class SandboxSchemaDriftError extends Error {
  readonly expected: readonly string[];
  readonly actual: readonly string[];

  constructor(expected: readonly string[], actual: readonly string[]) {
    const missing = expected.filter((t) => !actual.includes(t));
    const unexpected = actual.filter((t) => !expected.includes(t));
    const lines = [
      'Sandbox image schema drift — refusing to accept jobs.',
      `  worker expects scanTypes: [${expected.join(', ')}]`,
      `  image reports scanTypes:  [${actual.join(', ')}]`,
    ];
    if (missing.length > 0) {
      lines.push(`  missing in image:         [${missing.join(', ')}]`);
    }
    if (unexpected.length > 0) {
      lines.push(`  extra in image:           [${unexpected.join(', ')}]`);
    }
    lines.push('Rebuild the sandbox image: scripts/build-sandbox-image.sh');
    super(lines.join('\n'));
    this.name = 'SandboxSchemaDriftError';
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Compare two scanTypes lists ignoring order; throw {@link SandboxSchemaDriftError}
 * on mismatch. Exported separately so the comparison itself is unit-testable
 * without spinning up a real sandbox.
 */
export function assertSandboxSchemaMatches(
  expected: readonly string[],
  actual: readonly string[],
): void {
  const e = [...expected].sort();
  const a = [...actual].sort();
  if (e.length !== a.length || e.some((value, i) => value !== a[i])) {
    throw new SandboxSchemaDriftError(expected, actual);
  }
}

/**
 * Run one sandbox `selftest`, read back the image's schema snapshot, and assert
 * it matches the worker's `scanTypeSchema.options`. Call ONCE at worker boot
 * (see `apps/worker/src/main.ts`) before the queue worker is created so an
 * operator running a stale image can never accept and silently fail a job.
 *
 * Throws on any failure path:
 *   - sandbox could not run (Docker down, image missing) → infrastructure error,
 *     re-thrown so the worker process exits non-zero and the orchestrator restarts.
 *   - sandbox returned a non-selftest result → image is fundamentally broken;
 *     surface it instead of silently downgrading the check.
 *   - schemas disagree → {@link SandboxSchemaDriftError}.
 */
export async function verifySandboxImageMatchesSource(sandbox: ScanSandbox): Promise<void> {
  const job: SandboxJob = { op: 'selftest' };
  const outcome = await sandbox.runScanInSandbox(job);
  if (outcome.status !== 'completed') {
    throw new Error(
      `Sandbox selftest did not complete (status="${outcome.status}") — cannot verify image schema. ` +
        'Check that Docker is running and the anthrion-scan-runtime image exists.',
    );
  }
  const { result } = outcome;
  if (result.op !== 'selftest') {
    throw new Error(
      `Sandbox selftest returned op="${result.op}" (expected "selftest") — image is incompatible.`,
    );
  }
  assertSandboxSchemaMatches(scanTypeSchema.options, result.contract.scanTypes);
}
