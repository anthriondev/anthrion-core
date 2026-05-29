import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

/**
 * Thin wrapper over the Docker CLI (Part C decision: control Docker via the `docker`
 * CLI as a child process, not a socket SDK).
 *
 * Why the CLI over a socket library (e.g. dockerode):
 *   - Dependency-free and transparent — the exact `docker run` flags are auditable,
 *     which matters for a security sandbox.
 *   - Stable, well-documented interface; maps cleanly onto the run-once pattern.
 *   - Exit code + `docker inspect` give everything needed to classify an outcome.
 *
 * INJECTION SAFETY: every call uses `execFile`/`spawn` with an ARGUMENT ARRAY and no
 * shell, so target-controlled strings (scan ids, URLs) can never be interpreted as
 * shell. Never build a `docker ...` string and run it through a shell.
 *
 * Verified against Docker Engine 29.1.3 (server). Run `docker --version` to confirm
 * the host's version; the flags used here (`--memory`, `--cpus`, `--pids-limit`,
 * `--cap-drop`, `--security-opt`, `--network`, `--label`) are stable across 20.10+.
 */

const execFileAsync = promisify(execFile);

/** Docker label stamped on every scan container, so orphans can be found and swept. */
export const SANDBOX_LABEL_KEY = 'anthrion.sandbox';
export const SANDBOX_LABEL = `${SANDBOX_LABEL_KEY}=1`;

/** 8 MB cap on captured CLI output — large enough for any inspect/log, bounds runaway. */
const MAX_BUFFER = 8 * 1024 * 1024;

interface ExecResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  code: number | null;
}

/** Run `docker <args>` and resolve the result WITHOUT throwing on a non-zero exit. */
export async function tryDocker(args: readonly string[]): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync('docker', [...args], { maxBuffer: MAX_BUFFER });
    return { ok: true, stdout, stderr, code: 0 };
  } catch (error: unknown) {
    return {
      ok: false,
      stdout: readField(error, 'stdout'),
      stderr: readField(error, 'stderr'),
      code: readCode(error),
    };
  }
}

/** Run `docker <args>`, throwing a clear error (with stderr) on a non-zero exit. */
export async function docker(args: readonly string[]): Promise<string> {
  const result = await tryDocker(args);
  if (!result.ok) {
    throw new Error(
      `docker ${args.join(' ')} failed (exit ${result.code ?? 'unknown'}): ${result.stderr.trim() || result.stdout.trim()}`,
    );
  }
  return result.stdout;
}

/** True if the Docker daemon is reachable (used by tests/preflight). */
export async function dockerAvailable(): Promise<boolean> {
  const result = await tryDocker(['version', '--format', '{{.Server.Version}}']);
  return result.ok;
}

/** True if a local image with this ref exists. */
export async function imageExists(image: string): Promise<boolean> {
  return (await tryDocker(['image', 'inspect', image])).ok;
}

/**
 * Ensure the dedicated scan bridge network exists (idempotent). Creating a separate
 * bridge is what isolates scan containers from the host's other Docker networks
 * (Postgres/Redis/MinIO + other projects) while leaving outbound internet working.
 */
export async function ensureNetwork(name: string): Promise<void> {
  if ((await tryDocker(['network', 'inspect', name])).ok) {
    return;
  }
  // `bridge` driver = NAT to the internet; isolation from other bridges is automatic.
  await docker(['network', 'create', '--driver', 'bridge', '--label', SANDBOX_LABEL, name]);
}

/** Container runtime state needed to classify an outcome. */
export interface ContainerState {
  status: string;
  exitCode: number;
  /** True when the kernel OOM-killed the container (memory limit exceeded). */
  oomKilled: boolean;
}

/** Inspect a container's terminal state (status, exit code, OOM flag). */
export async function inspectContainerState(name: string): Promise<ContainerState> {
  const out = (
    await docker(['inspect', name, '--format', '{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}'])
  ).trim();
  const [status = 'unknown', exitCodeRaw = '0', oomRaw = 'false'] = out.split('|');
  return {
    status,
    exitCode: Number.parseInt(exitCodeRaw, 10) || 0,
    oomKilled: oomRaw === 'true',
  };
}

/** Force-stop a running container immediately (SIGKILL). Tolerant of already-exited. */
export async function killContainer(name: string): Promise<void> {
  await tryDocker(['kill', name]);
}

/** Remove a container (force — handles still-running). Tolerant of already-removed. */
export async function removeContainer(name: string): Promise<void> {
  await tryDocker(['rm', '-f', name]);
}

/** List ids of all scan-sandbox containers (running or stopped), by label. */
export async function listSandboxContainers(): Promise<string[]> {
  const out = await docker(['ps', '-aq', '--filter', `label=${SANDBOX_LABEL_KEY}`]);
  return out
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function readField(error: unknown, field: 'stdout' | 'stderr'): string {
  if (typeof error === 'object' && error !== null && field in error) {
    const value = (error as Record<string, unknown>)[field];
    return typeof value === 'string' ? value : '';
  }
  return '';
}

function readCode(error: unknown): number | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const value = (error as Record<string, unknown>).code;
    return typeof value === 'number' ? value : null;
  }
  return null;
}
