import type { Finding } from '@anthrion/scan-engine';
import type { ScanReport } from '@anthrion/sandbox-runtime';
import type { ScanJobPayload, ScanJobType } from '@anthrion/shared';

import type { ScanSandbox, SandboxOutcome } from './sandbox/manager';
import { buildScanSandboxJob, defaultBuildScanJobDeps, type BuildScanJobDeps } from './sandbox/scan-config';

/**
 * Scan runner (T3.3, Parts B–D): the full path from a validated job payload to a
 * scan result. Maps payload → `ScanConfig` (Part A), runs it in the sandbox (T3.2),
 * then maps the `SandboxOutcome` → a {@link ScanRunResult} (Part C).
 *
 * T3.3 vs T3.4: this produces the result (success/failure + reason + findings). It
 * does NOT persist anything — storing the `Scan` row + `Finding`s (status
 * QUEUED/RUNNING/DONE/FAILED) is T3.4, which consumes this {@link ScanRunResult}.
 */

/** Why a scan failed. `lifetime-timeout`/`memory-oom` come from a force-stopped sandbox.
 * `target-unreachable` means the scan made zero meaningful contact with its target
 * (web: page failed to load; AI: every Layer 1 probe failed network-layer). A scan
 * that never touched its target is FAILED, not a billable DONE with zero coverage. */
export type ScanFailureReason =
  | 'mapping-error'
  | 'lifetime-timeout'
  | 'memory-oom'
  | 'sandbox-error'
  | 'invalid-result'
  | 'target-unreachable';

export interface ScanRunSucceeded {
  status: 'succeeded';
  scanId: string;
  scanType: ScanJobType;
  /** Findings collected from the engine (already Zod-validated crossing the sandbox boundary). */
  findings: Finding[];
  /** Honest engine report (coverage gaps, layer outcomes) — see contract `ScanReport`. */
  report: ScanReport;
  durationMs: number;
}

export interface ScanRunFailed {
  status: 'failed';
  scanId: string;
  scanType: ScanJobType;
  reason: ScanFailureReason;
  message: string;
  durationMs: number;
}

/**
 * Result of a scan run. A failure is NEVER represented as "succeeded with 0 findings"
 * (Context §3 / Part C: truncated or failed ≠ safe). T3.4 maps `succeeded` → DONE and
 * `failed` → FAILED (with the reason).
 */
export type ScanRunResult = ScanRunSucceeded | ScanRunFailed;

export interface ExecuteScanOptions {
  /** Override the payload→job build deps (tests). Defaults to env-derived knobs. */
  deps?: BuildScanJobDeps;
  /** Sink for raw progress-event lines streamed from the sandbox stdout (T4.2). */
  onEvent?: (rawJson: string) => void;
}

/**
 * Execute a scan end-to-end: map → run in sandbox → classify outcome.
 *
 * Failure policy (Part D):
 *   - mapping failure (bad/inconsistent data, missing key for an AI scan) → `failed`
 *     with `mapping-error` (permanent — not retried).
 *   - the sandbox manager THROWS only on an INFRASTRUCTURE failure (e.g. the Docker
 *     daemon is unreachable); that propagates so BullMQ can retry (T3.1 attempts:3).
 *   - a scan-level failure (limit hit, engine error, invalid output) comes back as a
 *     `SandboxOutcome` and is mapped to a `failed` result (no pointless retry against
 *     the same target).
 */
export async function executeScan(
  payload: ScanJobPayload,
  sandbox: ScanSandbox,
  options: ExecuteScanOptions = {},
): Promise<ScanRunResult> {
  const startedAt = Date.now();
  const deps = options.deps ?? defaultBuildScanJobDeps();

  let scanJob;
  try {
    scanJob = buildScanSandboxJob(payload, deps);
  } catch (cause) {
    return fail(payload, 'mapping-error', `could not build scan config: ${messageOf(cause)}`, Date.now() - startedAt);
  }

  // A thrown error here = infrastructure failure → propagates → BullMQ retries.
  const outcome = await sandbox.runScanInSandbox(scanJob, {
    scanId: payload.scanId,
    ...(options.onEvent !== undefined ? { onEvent: options.onEvent } : {}),
  });
  return mapOutcomeToResult(payload, outcome, Date.now() - startedAt);
}

/**
 * Map a `SandboxOutcome` to a `ScanRunResult` (Part C). `completed` + a valid scan
 * result → success; `force-stopped`/`error`/wrong-result → failure with a reason.
 */
export function mapOutcomeToResult(
  payload: ScanJobPayload,
  outcome: SandboxOutcome,
  durationMs: number,
): ScanRunResult {
  switch (outcome.status) {
    case 'force-stopped':
      // A resource limit was hit → the scan is truncated → FAILED, not "0 findings".
      return fail(
        payload,
        outcome.reason,
        `scan force-stopped (${outcome.reason}) after ${outcome.durationMs}ms`,
        durationMs,
      );
    case 'error':
      return fail(payload, 'sandbox-error', outcome.message, durationMs);
    case 'completed': {
      const { result } = outcome;
      // The manager already Zod-validated the result; narrow it to the scan shape.
      if (result.op !== 'scan') {
        return fail(payload, 'invalid-result', `sandbox returned op="${result.op}", expected "scan"`, durationMs);
      }
      // Zero meaningful contact with the target → FAILED, not DONE with zero coverage.
      // - Web: page.goto could not load the target page.
      // - AI:  every Layer 1 probe failed network-layer (no probe executed at all).
      // - API: the baseline reachability check yielded no response from the target.
      // A scan that never touched its target must not appear as a billable success.
      if (result.report.scanType === 'web-app-vuln' && !result.report.pageLoaded) {
        const detail = result.report.loadError ?? result.report.outcome;
        return fail(payload, 'target-unreachable', `target page could not be loaded: ${detail}`, durationMs);
      }
      if (result.report.scanType === 'ai-llm-attack' && result.report.layer1Outcome === 'target-unreachable') {
        return fail(
          payload,
          'target-unreachable',
          `no Layer 1 probe could contact the target (${result.report.layer1Stats.notExecuted}/${result.report.layer1Stats.total} did not execute)`,
          durationMs,
        );
      }
      if (result.report.scanType === 'api-scan' && result.report.outcome === 'target-unreachable') {
        return fail(
          payload,
          'target-unreachable',
          `API target unreachable: baseline request did not yield a response (${result.report.stats.notExecuted}/${result.report.stats.total} probes did not execute)`,
          durationMs,
        );
      }
      if (result.report.scanType === 'web3-dapp' && !result.report.pageLoaded) {
        const detail = result.report.loadError ?? result.report.l1Outcome;
        return fail(payload, 'target-unreachable', `dApp page could not be loaded: ${detail}`, durationMs);
      }
      return {
        status: 'succeeded',
        scanId: payload.scanId,
        scanType: payload.scanType,
        findings: result.findings,
        report: result.report,
        durationMs,
      };
    }
  }
}

function fail(
  payload: ScanJobPayload,
  reason: ScanFailureReason,
  message: string,
  durationMs: number,
): ScanRunFailed {
  return { status: 'failed', scanId: payload.scanId, scanType: payload.scanType, reason, message, durationMs };
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
