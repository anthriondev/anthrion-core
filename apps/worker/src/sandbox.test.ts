import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { sandboxResultSchema } from '@anthrion/sandbox-runtime';

import { loadSandboxConfig } from './sandbox/config';
import { dockerAvailable, imageExists, tryDocker } from './sandbox/docker';
import {
  DockerSandboxManager,
  buildSandboxRunArgs,
  resolveSandboxConfig,
} from './sandbox/manager';

/**
 * Sandbox manager integration tests (T3.2, Part D) — against REAL Docker, not mocks.
 *
 * Prerequisites (a clean run depends on them, like the T1.2 real-Postgres tests):
 *   - the Docker daemon is reachable, and
 *   - the scan-runtime image is built (scripts/build-sandbox-image.sh).
 * If either is missing the Docker-dependent tests SKIP with a clear reason (they are
 * never faked). The host's internal services (anthrion-postgres :5436, anthrion-redis
 * :6380, anthrion-minio :9002) being up makes the isolation test meaningful.
 */

const config = loadSandboxConfig();
const manager = new DockerSandboxManager(config);

/** True iff a container with exactly this name exists (running or stopped). */
async function containerExists(name: string): Promise<boolean> {
  const result = await tryDocker(['ps', '-aq', '--filter', `name=^${name}$`]);
  return result.ok && result.stdout.trim().length > 0;
}

/** Assert `args` contains `flag` immediately followed by `value`. */
function assertFlagValue(args: readonly string[], flag: string, value: string): void {
  const i = args.indexOf(flag);
  assert.notEqual(i, -1, `expected ${flag} in args`);
  assert.equal(args[i + 1], value, `expected ${flag} ${value}`);
}

describe('DockerSandboxManager (real Docker)', () => {
  let skipReason: string | undefined;

  before(async () => {
    if (!(await dockerAvailable())) {
      skipReason = 'Docker daemon not available';
      return;
    }
    if (!(await imageExists(config.image))) {
      skipReason = `image "${config.image}" not built — run scripts/build-sandbox-image.sh`;
    }
  });

  after(async () => {
    // Guarantee a clean host even if a test failed mid-run (DoD: `docker ps -a` clean).
    if (skipReason === undefined) {
      await manager.sweepOrphans();
    }
  });

  // ── Resource limits are applied and configurable (pure — no Docker) ──────────

  test('resource limits + isolation flags are applied and configurable', () => {
    const base = loadSandboxConfig();
    const args = buildSandboxRunArgs({ cfg: base, containerName: 'c', scanId: 's', allowDiagnostics: false });

    assertFlagValue(args, '--memory', `${base.memoryMb}m`);
    assertFlagValue(args, '--memory-swap', `${base.memoryMb}m`); // swap disabled → clean OOM
    assertFlagValue(args, '--cpus', String(base.cpus));
    assertFlagValue(args, '--pids-limit', String(base.pidsLimit));
    assertFlagValue(args, '--network', base.network);
    assertFlagValue(args, '--cap-drop', 'ALL');
    assert.ok(args.includes('--read-only'));
    assert.ok(args.includes('--init'));
    // Diagnostics are OFF on the normal path.
    assert.equal(args.includes(`ANTHRION_SANDBOX_DIAG=1`), false);

    // Overrides flow through (configurable, Context §3).
    const overridden = resolveSandboxConfig(base, { memoryMb: 512, cpus: 0.5 });
    const args2 = buildSandboxRunArgs({ cfg: overridden, containerName: 'c', scanId: 's', allowDiagnostics: true });
    assertFlagValue(args2, '--memory', '512m');
    assertFlagValue(args2, '--cpus', '0.5');
    assert.ok(args2.includes(`ANTHRION_SANDBOX_DIAG=1`));
  });

  // ── Create → run → receive validated output → destroy ───────────────────────

  test('selftest: container is created, runs the engine, returns validated output, then destroyed', { timeout: 90_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const outcome = await manager.runScanInSandbox({ op: 'selftest' }, { scanId: 'it-selftest' });

    assert.equal(outcome.status, 'completed');
    if (outcome.status !== 'completed') {
      return;
    }
    // The result already passed the manager's Zod gate; re-assert it here explicitly.
    assert.doesNotThrow(() => sandboxResultSchema.parse(outcome.result));
    assert.equal(outcome.result.op, 'selftest');
    if (outcome.result.op !== 'selftest') {
      return;
    }
    // Real engine output crossed the boundary.
    assert.ok(outcome.result.engine.findingsCount > 0, 'engine should produce findings');
    // Image is self-contained: Chromium is present AND launches under the hardening.
    assert.equal(outcome.result.chromium.present, true);
    assert.equal(outcome.result.chromium.launched, true);
    // Runs as the non-root image user (defense-in-depth).
    assert.equal(outcome.result.runtime.user, 'uid=1001');
    // Destroyed on the success path.
    assert.equal(await containerExists(outcome.containerName), false, 'container must be destroyed');
  });

  // ── Cleanup on the failure path ─────────────────────────────────────────────

  test('error path: a failing run is classified `error` and the container is still destroyed', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    // A diagnostic op WITHOUT allowDiagnostics → the entrypoint rejects it → exit 1.
    const outcome = await manager.runScanInSandbox({ op: 'sleep', durationMs: 10 }, { scanId: 'it-error' });

    assert.equal(outcome.status, 'error');
    if (outcome.status !== 'error') {
      return;
    }
    assert.match(outcome.message, /disabled/i);
    assert.equal(await containerExists(outcome.containerName), false, 'container must be destroyed on error');
  });

  // ── Lifetime limit → force-stop, distinguishable from a normal finish ────────

  test('lifetime limit: an over-running container is force-stopped (lifetime-timeout), not "completed"', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const outcome = await manager.runScanInSandbox(
      { op: 'sleep', durationMs: 120_000 },
      { scanId: 'it-timeout', allowDiagnostics: true, overrides: { lifetimeMs: 2_000 } },
    );

    assert.equal(outcome.status, 'force-stopped');
    if (outcome.status !== 'force-stopped') {
      return;
    }
    assert.equal(outcome.reason, 'lifetime-timeout');
    assert.equal(await containerExists(outcome.containerName), false);
  });

  // ── Memory limit → OOM force-stop ───────────────────────────────────────────

  test('memory limit: an over-allocating container is OOM-killed and reported force-stopped', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const outcome = await manager.runScanInSandbox(
      { op: 'alloc', megabytes: 512, holdMs: 8_000 },
      { scanId: 'it-oom', allowDiagnostics: true, overrides: { memoryMb: 256 } },
    );

    assert.equal(outcome.status, 'force-stopped');
    if (outcome.status !== 'force-stopped') {
      return;
    }
    assert.equal(outcome.reason, 'memory-oom');
    assert.equal(await containerExists(outcome.containerName), false);
  });

  // ── Network isolation (security proof) ──────────────────────────────────────

  test('network isolation: outbound internet works, host-internal services are unreachable', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const outcome = await manager.runScanInSandbox(
      {
        op: 'netcheck',
        targets: [
          { label: 'internet', host: 'example.com', port: 80, timeoutMs: 4_000 },
          { label: 'host-postgres', host: 'gateway', port: 5436, timeoutMs: 4_000 },
          { label: 'host-redis', host: 'gateway', port: 6380, timeoutMs: 4_000 },
          { label: 'host-minio', host: 'gateway', port: 9002, timeoutMs: 4_000 },
        ],
      },
      { scanId: 'it-netiso', allowDiagnostics: true },
    );

    assert.equal(outcome.status, 'completed');
    if (outcome.status !== 'completed' || outcome.result.op !== 'netcheck') {
      return;
    }
    const reachable = new Map(outcome.result.results.map((r) => [r.label, r.reachable]));
    assert.equal(reachable.get('internet'), true, 'outbound internet must be reachable');
    assert.equal(reachable.get('host-postgres'), false, 'host Postgres must be blocked');
    assert.equal(reachable.get('host-redis'), false, 'host Redis must be blocked');
    assert.equal(reachable.get('host-minio'), false, 'host MinIO must be blocked');
    assert.equal(await containerExists(outcome.containerName), false);
  });

  // ── Sweep leftover containers ───────────────────────────────────────────────

  test('sweepOrphans removes leftover labelled containers', { timeout: 60_000 }, async (t) => {
    if (skipReason !== undefined) {
      t.skip(skipReason);
      return;
    }
    const name = `anthrion-scan-orphan-${Date.now()}`;
    // A labelled, detached container the manager did NOT create (simulates a crash).
    await tryDocker(['run', '-d', '--name', name, '--label', 'anthrion.sandbox=1', '--entrypoint', 'sleep', config.image, '300']);
    assert.equal(await containerExists(name), true, 'orphan should exist before sweep');

    const removed = await manager.sweepOrphans();
    assert.ok(removed >= 1, 'sweep should remove at least the orphan');
    assert.equal(await containerExists(name), false, 'orphan should be gone after sweep');
  });
});
