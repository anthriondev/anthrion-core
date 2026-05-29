import assert from 'node:assert/strict';
import { test } from 'node:test';

import { scanTypeSchema } from '@anthrion/scan-engine';
import type { Finding } from '@anthrion/scan-engine';
import type { SandboxJob, SandboxResult } from '@anthrion/sandbox-runtime';

import type { ScanSandbox, SandboxOutcome, SandboxRunOptions } from './manager';
import {
  SandboxSchemaDriftError,
  assertSandboxSchemaMatches,
  verifySandboxImageMatchesSource,
} from './drift-guard';

/**
 * T-FIX.9 tests — the sandbox-image-vs-source drift guard. Unit tests use a stub
 * `ScanSandbox` so the guard's decision logic is exercised without spinning up
 * Docker; the production wiring lives in apps/worker/src/main.ts.
 */

class StubSandbox implements ScanSandbox {
  constructor(private readonly outcome: SandboxOutcome) {}

  runScanInSandbox(_job: SandboxJob, _options?: SandboxRunOptions): Promise<SandboxOutcome> {
    return Promise.resolve(this.outcome);
  }
}

function completed(result: SandboxResult): SandboxOutcome {
  return {
    status: 'completed',
    containerName: 'stub',
    exitCode: 0,
    durationMs: 1,
    result,
  };
}

function selftestResult(scanTypes: readonly string[]): SandboxResult {
  return {
    op: 'selftest',
    engine: {
      layer1Outcome: 'passed',
      probesExecuted: 0,
      findingsCount: 0,
      findings: [] satisfies Finding[],
    },
    chromium: { executablePath: '/x', present: true, launched: true },
    runtime: { node: 'v24.0.0', user: 'pwuser' },
    contract: { scanTypes: [...scanTypes] },
  };
}

// ── pure comparison ─────────────────────────────────────────────────────────

test('assertSandboxSchemaMatches: same set in same order is OK', () => {
  assertSandboxSchemaMatches(
    ['ai-llm-attack', 'web-app-vuln', 'api-scan'],
    ['ai-llm-attack', 'web-app-vuln', 'api-scan'],
  );
});

test('assertSandboxSchemaMatches: same set in different order is OK (order-insensitive)', () => {
  assertSandboxSchemaMatches(
    ['ai-llm-attack', 'web-app-vuln', 'api-scan'],
    ['api-scan', 'ai-llm-attack', 'web-app-vuln'],
  );
});

test('assertSandboxSchemaMatches: missing scanType in image throws SandboxSchemaDriftError', () => {
  assert.throws(
    () =>
      assertSandboxSchemaMatches(
        ['ai-llm-attack', 'web-app-vuln', 'api-scan'],
        // The exact regression that fired in production — a stale image with the
        // 2-element scanTypeSchema (no api-scan).
        ['ai-llm-attack', 'web-app-vuln'],
      ),
    (err: unknown) => {
      if (!(err instanceof SandboxSchemaDriftError)) return false;
      assert.match(err.message, /missing in image:\s+\[api-scan\]/);
      assert.match(err.message, /build-sandbox-image\.sh/);
      return true;
    },
  );
});

test('assertSandboxSchemaMatches: unexpected scanType in image also throws', () => {
  // Reverse direction — the image is AHEAD of the worker (e.g. new scan type
  // added in a future commit, worker not yet rebuilt). Either direction means
  // drift; both must fail closed.
  assert.throws(
    () =>
      assertSandboxSchemaMatches(
        ['ai-llm-attack', 'web-app-vuln'],
        ['ai-llm-attack', 'web-app-vuln', 'web3-dapp-scan'],
      ),
    (err: unknown) => {
      if (!(err instanceof SandboxSchemaDriftError)) return false;
      assert.match(err.message, /extra in image:\s+\[web3-dapp-scan\]/);
      return true;
    },
  );
});

// ── verifySandboxImageMatchesSource: end-to-end with a stub sandbox ──────────

test('verifySandboxImageMatchesSource: image matching the worker passes', async () => {
  // Use the worker's actual `scanTypeSchema.options` so this test stays honest
  // even if the enum grows (any new value is reflected in both sides).
  const sandbox = new StubSandbox(completed(selftestResult(scanTypeSchema.options)));
  await verifySandboxImageMatchesSource(sandbox);
});

test('verifySandboxImageMatchesSource: stale image (missing scanType) throws SandboxSchemaDriftError', async () => {
  const stale = scanTypeSchema.options.filter((t) => t !== 'api-scan');
  // Sanity: only meaningful if api-scan is in the source set.
  assert.notEqual(stale.length, scanTypeSchema.options.length);
  const sandbox = new StubSandbox(completed(selftestResult(stale)));
  await assert.rejects(
    verifySandboxImageMatchesSource(sandbox),
    (err: unknown) => err instanceof SandboxSchemaDriftError,
  );
});

test('verifySandboxImageMatchesSource: sandbox error outcome is surfaced as a clear error', async () => {
  const sandbox = new StubSandbox({
    status: 'error',
    containerName: 'stub',
    exitCode: 1,
    durationMs: 1,
    message: 'docker daemon unreachable',
    stderr: '',
  });
  await assert.rejects(
    verifySandboxImageMatchesSource(sandbox),
    (err: unknown) =>
      err instanceof Error && /did not complete/.test(err.message) && /status="error"/.test(err.message),
  );
});

test('verifySandboxImageMatchesSource: wrong op in result is surfaced (broken image)', async () => {
  const sandbox = new StubSandbox(
    completed({ op: 'sleep', sleptMs: 0 }),
  );
  await assert.rejects(
    verifySandboxImageMatchesSource(sandbox),
    (err: unknown) =>
      err instanceof Error && /op="sleep"/.test(err.message) && /incompatible/i.test(err.message),
  );
});
