import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

import {
  DIAGNOSTICS_ENV_VAR,
  EVENT_LINE_PREFIX,
  parseSandboxResult,
  type SandboxJob,
  type SandboxResult,
} from '@anthrion/sandbox-runtime';

import { loadSandboxConfig, type SandboxConfig } from './config';
import {
  ensureNetwork,
  inspectContainerState,
  killContainer,
  listSandboxContainers,
  removeContainer,
  SANDBOX_LABEL,
  SANDBOX_LABEL_KEY,
  type ContainerState,
} from './docker';

/**
 * Per-scan Docker sandbox manager (T3.2, Part B).
 *
 * Implements the run-once container pattern (ARCHITECTURE.md §5, Pattern A): for
 * each scan a fresh container is created with resource limits + network isolation,
 * the job is fed in over stdin, the result is read off stdout, and the container is
 * destroyed — on EVERY path (success, failure, timeout, error) via `finally`.
 *
 * T3.2 vs T3.3: this manager proves the sandbox path (create → run → receive →
 * destroy) and classifies the outcome. Mapping a scan-job payload → `ScanConfig`
 * and running the FULL engine (both scan types) inside is T3.3; this manager will be
 * called from `processScanJob` then. The `op: 'selftest'` job runs a REAL but
 * limited engine pass to prove the path — not a hidden mock.
 */

/** Reason a container was force-stopped (a resource limit was hit) — never "completed". */
export type ForcedReason = 'lifetime-timeout' | 'memory-oom';

/** Container exited normally (code 0) and produced a valid result. */
export interface SandboxCompleted {
  status: 'completed';
  containerName: string;
  exitCode: number;
  durationMs: number;
  result: SandboxResult;
}

/**
 * Container was force-stopped because a limit was hit (worker-killed on lifetime
 * timeout, or kernel OOM-killed on the memory cap). The scan is truncated, NOT
 * "completed with zero findings" (Context §3: truncated ≠ safe). T3.4 maps this to
 * scan status FAILED.
 */
export interface SandboxForceStopped {
  status: 'force-stopped';
  containerName: string;
  reason: ForcedReason;
  exitCode: number;
  durationMs: number;
  stderr: string;
}

/** Container failed for a non-limit reason (engine threw, bad output, image missing, …). */
export interface SandboxErrored {
  status: 'error';
  containerName: string;
  exitCode: number | null;
  durationMs: number;
  message: string;
  stderr: string;
}

/**
 * Outcome of a sandbox run. The worker (and T3.4) decide scan status from `status`:
 * only `completed` is a normal finish — `force-stopped` and `error` are FAILED paths.
 */
export type SandboxOutcome = SandboxCompleted | SandboxForceStopped | SandboxErrored;

export interface SandboxRunOptions {
  /** Correlation id for naming/labelling the container (the Scan id, T3.4). */
  scanId?: string;
  /** Explicit container name (tests). Defaults to a generated unique name. */
  containerName?: string;
  /** Enable the in-container diagnostic ops (tests only — never on the scan path). */
  allowDiagnostics?: boolean;
  /** Per-run config overrides (tests use tiny limits to trip them deterministically). */
  overrides?: Partial<SandboxConfig>;
  /**
   * Called for each progress-event line the container streams to stdout (T4.2). The
   * argument is the raw JSON payload (prefix stripped) — still UNTRUSTED; the caller
   * validates it before use. The manager only does transport (line splitting + prefix
   * routing); it knows nothing about Redis or the event schema.
   */
  onEvent?: (rawJson: string) => void;
}

/**
 * The sandbox capability the scan runner depends on. Narrow interface (just "run a
 * job, get a classified outcome") so the consumer/runner can be unit-tested with a
 * stub, while production uses {@link DockerSandboxManager} against real Docker.
 */
export interface ScanSandbox {
  runScanInSandbox(job: SandboxJob, options?: SandboxRunOptions): Promise<SandboxOutcome>;
}

/** Max bytes captured per stream — bounds a chatty/runaway container's output. */
const STREAM_CAP_BYTES = 8 * 1024 * 1024;

export class DockerSandboxManager implements ScanSandbox {
  private readonly config: SandboxConfig;

  constructor(config: SandboxConfig = loadSandboxConfig()) {
    this.config = config;
  }

  /**
   * Run one job in a fresh sandbox container and return a classified outcome. The
   * container is always destroyed before this resolves (success, failure, timeout,
   * or error) — see the `finally` block.
   */
  async runScanInSandbox(job: SandboxJob, options: SandboxRunOptions = {}): Promise<SandboxOutcome> {
    const cfg = resolveSandboxConfig(this.config, options.overrides);
    const containerName = options.containerName ?? generateContainerName(options.scanId);

    // The dedicated bridge network is what isolates the container from host-internal
    // services while keeping outbound internet (Part §4). Idempotent.
    await ensureNetwork(cfg.network);

    const args = buildSandboxRunArgs({
      cfg,
      containerName,
      scanId: options.scanId,
      allowDiagnostics: options.allowDiagnostics === true,
    });

    const startedAt = Date.now();
    try {
      const run = await this.spawnAndWait(args, job, cfg.lifetimeMs, containerName, options.onEvent);
      const durationMs = Date.now() - startedAt;

      // Best-effort terminal-state read; container still exists here (removed in finally).
      let state: ContainerState | undefined;
      try {
        state = await inspectContainerState(containerName);
      } catch {
        state = undefined;
      }

      return classifyOutcome({ containerName, durationMs, run, state });
    } finally {
      // Destroy on every path — containers must never accumulate (Part B.3).
      await removeContainer(containerName);
    }
  }

  /**
   * Remove any leftover scan-sandbox containers (by label). Defensive cleanup for a
   * worker crash mid-scan; safe to call on startup. Returns how many were removed.
   */
  async sweepOrphans(): Promise<number> {
    const ids = await listSandboxContainers();
    await Promise.all(ids.map((id) => removeContainer(id)));
    return ids.length;
  }

  /**
   * Spawn `docker run -i`, feed the job over stdin, capture stdout/stderr, and
   * enforce the wall-clock lifetime: on expiry the container is force-killed and
   * `timedOut` is set so the outcome can be classified as a forced stop.
   */
  private spawnAndWait(
    args: readonly string[],
    job: SandboxJob,
    lifetimeMs: number,
    containerName: string,
    onEvent: ((rawJson: string) => void) | undefined,
  ): Promise<RunResult> {
    return new Promise<RunResult>((resolve, reject) => {
      const child = spawn('docker', [...args], { stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let spawnFailed = false;
      // Line buffer for streaming: stdout arrives in arbitrary chunks, so we hold the
      // trailing partial line until its newline arrives (T4.2). The full `stdout` is
      // ALSO accumulated so the final result-line parse (T3.3) keeps working.
      let lineBuffer = '';

      const handleLine = (line: string): void => {
        // Route progress-event lines to the caller while the scan runs. The result line
        // and ordinary logs are ignored here (the result is parsed from full stdout).
        if (onEvent !== undefined && line.startsWith(EVENT_LINE_PREFIX)) {
          onEvent(line.slice(EVENT_LINE_PREFIX.length));
        }
      };

      const timer = setTimeout(() => {
        timedOut = true;
        // Decisive SIGKILL via Docker (not a grace stop) so the forced stop is clear-cut.
        void killContainer(containerName);
      }, lifetimeMs);

      child.stdout.on('data', (chunk: Buffer) => {
        const text = chunk.toString('utf8');
        if (stdout.length < STREAM_CAP_BYTES) {
          stdout += text;
        }
        // Split into complete lines, streaming event lines as they arrive.
        lineBuffer += text;
        let newlineIndex = lineBuffer.indexOf('\n');
        while (newlineIndex !== -1) {
          handleLine(lineBuffer.slice(0, newlineIndex));
          lineBuffer = lineBuffer.slice(newlineIndex + 1);
          newlineIndex = lineBuffer.indexOf('\n');
        }
      });
      child.stderr.on('data', (chunk: Buffer) => {
        if (stderr.length < STREAM_CAP_BYTES) {
          stderr += chunk.toString('utf8');
        }
      });

      child.on('error', (err) => {
        // e.g. `docker` not on PATH — the daemon/CLI is a documented prerequisite.
        spawnFailed = true;
        clearTimeout(timer);
        reject(err);
      });

      // Feed the job, then close stdin so the in-container reader completes.
      child.stdin.on('error', () => {
        // Ignore EPIPE if the container exits before reading stdin; the close/exit
        // handler below carries the real outcome.
      });
      child.stdin.write(JSON.stringify(job));
      child.stdin.end();

      child.on('close', (code, signal) => {
        if (spawnFailed) {
          return;
        }
        clearTimeout(timer);
        resolve({ code, signal, stdout, stderr, timedOut });
      });
    });
  }
}

interface RunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function classifyOutcome(input: {
  containerName: string;
  durationMs: number;
  run: RunResult;
  state: ContainerState | undefined;
}): SandboxOutcome {
  const { containerName, durationMs, run, state } = input;
  const exitCode = state?.exitCode ?? run.code ?? -1;

  // 1) OOM first — the kernel acted on the memory limit, regardless of our timer.
  if (state?.oomKilled === true) {
    return { status: 'force-stopped', containerName, reason: 'memory-oom', exitCode, durationMs, stderr: run.stderr };
  }

  // 2) Worker-enforced lifetime timeout — we SIGKILLed it.
  if (run.timedOut) {
    return {
      status: 'force-stopped',
      containerName,
      reason: 'lifetime-timeout',
      exitCode,
      durationMs,
      stderr: run.stderr,
    };
  }

  // 3) Clean exit → the result must parse and validate, else it is an error.
  if (run.code === 0) {
    try {
      const result = parseSandboxResult(run.stdout);
      return { status: 'completed', containerName, exitCode: 0, durationMs, result };
    } catch (cause) {
      return {
        status: 'error',
        containerName,
        exitCode: 0,
        durationMs,
        message: cause instanceof Error ? cause.message : String(cause),
        stderr: run.stderr,
      };
    }
  }

  // 4) Anything else is an error (engine threw, image missing, non-zero exit).
  return {
    status: 'error',
    containerName,
    exitCode: run.code,
    durationMs,
    message: errorMessageFrom(run),
    stderr: run.stderr,
  };
}

/** Prefer the in-container error envelope's message; fall back to stderr/exit code. */
function errorMessageFrom(run: RunResult): string {
  try {
    const result = parseSandboxResult(run.stdout);
    if (result.op === 'error') {
      return result.message;
    }
  } catch {
    // no parseable result — fall through
  }
  const trimmed = run.stderr.trim();
  if (trimmed.length > 0) {
    return trimmed.split('\n').slice(-1)[0] ?? trimmed;
  }
  return `Container exited with code ${run.code ?? 'unknown'}${run.signal ? ` (signal ${run.signal})` : ''}.`;
}

/** Resolve effective config = base config with optional per-run overrides applied. */
export function resolveSandboxConfig(base: SandboxConfig, overrides?: Partial<SandboxConfig>): SandboxConfig {
  return {
    image: overrides?.image ?? base.image,
    network: overrides?.network ?? base.network,
    memoryMb: overrides?.memoryMb ?? base.memoryMb,
    cpus: overrides?.cpus ?? base.cpus,
    pidsLimit: overrides?.pidsLimit ?? base.pidsLimit,
    lifetimeMs: overrides?.lifetimeMs ?? base.lifetimeMs,
    shmSizeMb: overrides?.shmSizeMb ?? base.shmSizeMb,
  };
}

/** Docker-name-safe unique container name derived from the scan id. */
function generateContainerName(scanId?: string): string {
  const safeId = (scanId ?? 'scan').replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 40);
  return `anthrion-scan-${safeId}-${randomBytes(4).toString('hex')}`;
}

/**
 * Build the exact `docker run` argument array (resource limits + network isolation +
 * hardening). Exported so a unit test can assert the limits are applied and
 * configurable without spinning a container.
 */
export function buildSandboxRunArgs(input: {
  cfg: SandboxConfig;
  containerName: string;
  scanId: string | undefined;
  allowDiagnostics: boolean;
}): string[] {
  const { cfg, containerName, scanId, allowDiagnostics } = input;
  const args: string[] = [
    'run',
    '-i', // attach stdin so we can feed the job; capture stdout/stderr
    '--init', // tini as PID 1 → reaps Chromium's child processes, forwards signals
    '--name',
    containerName,
    '--label',
    SANDBOX_LABEL,
    '--label',
    `anthrion.scanId=${(scanId ?? 'none').replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 64)}`,
    // ── network isolation (Part §4): dedicated bridge → no host-internal services,
    //    outbound internet only.
    '--network',
    cfg.network,
    // ── resource limits (Part §3): loose safety nets, not tight knives.
    '--memory',
    `${cfg.memoryMb}m`,
    '--memory-swap',
    `${cfg.memoryMb}m`, // == memory → swap disabled → clean, detectable OOM
    '--cpus',
    String(cfg.cpus),
    '--pids-limit',
    String(cfg.pidsLimit),
    // ── defense-in-depth hardening: the container runs untrusted target input.
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--read-only', // immutable rootfs…
    '--tmpfs',
    '/tmp:rw,exec,size=512m', // …with writable scratch for Chromium's profile/tmp
    '--shm-size',
    `${cfg.shmSizeMb}m`, // Chromium shared memory (paired with --disable-dev-shm-usage)
    '--env',
    'HOME=/tmp', // keep any home-dir writes on the writable tmpfs
  ];

  if (allowDiagnostics) {
    args.push('--env', `${DIAGNOSTICS_ENV_VAR}=1`);
  }

  args.push(cfg.image);
  return args;
}

export { SANDBOX_LABEL_KEY };
