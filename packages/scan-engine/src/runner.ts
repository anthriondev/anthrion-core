import { findingSchema, type Evidence, type Finding } from './finding';
import type { StaticProbe } from './probe';
import { LAYER1_PROBES } from './probes';
import { emitProgress, type ScanProgressCallback } from './progress';
import { TargetAdapterError, type ScanTarget, type TargetResponse } from './target';

/**
 * Layer 1 runner (T2.3, Part C). Executes static probes against a `ScanTarget`
 * and collects normalised `Finding`s.
 *
 * The runner ONLY uses `ScanTarget.send()` — it does not know (and must not
 * know) the target type. This means the same probes run against both adapters
 * (endpoint and system-prompt) without modification (ARCHITECTURE.md §4.1).
 *
 * Target failure handling (Part C.4): `send()` may throw `TargetAdapterError`.
 * An unreachable target does NOT mean safe — probes that could not execute are
 * marked `not-executed`, not treated as passing. See `passedLayer1` and
 * `outcome` semantics below.
 */

/** Outcome status of a single probe run against a target. */
export type ProbeStatus = 'detected' | 'clean' | 'not-executed';

/** Result of a single probe. `finding` is present iff `detected`; `error` is present iff `not-executed`. */
export interface Layer1ProbeResult {
  probeId: string;
  technique: string;
  category: Finding['category'];
  status: ProbeStatus;
  /** Explanation of the detector decision (positive and negative) or reason for not executing. */
  rationale: string;
  /** Normalised finding — only present when `status === 'detected'`. */
  finding?: Finding;
  /** `TargetAdapterError` message — only present when `status === 'not-executed'`. */
  error?: string;
}

/**
 * Summary outcome of a single Layer 1 run:
 * - `vulnerable`        — ≥1 probe triggered (findings present).
 * - `passed`           — all probes executed, zero findings.
 * - `passed-with-gaps` — some probes executed with no findings, BUT some failed
 *                        to execute (incomplete coverage).
 * - `target-unreachable` — no probe executed successfully at all.
 */
export type Layer1Outcome = 'vulnerable' | 'passed' | 'passed-with-gaps' | 'target-unreachable';

export interface Layer1Stats {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
}

/**
 * Layer 1 report. This shape gives Layer 2 (T2.5) enough information to know
 * which targets "passed Layer 1" (`ARCHITECTURE.md` §4.2) without needing to
 * build Layer 2 logic yet.
 */
export interface Layer1Report {
  outcome: Layer1Outcome;
  /**
   * True if Layer 1 RAN and found no obvious vulnerabilities
   * (`detected === 0 && executed > 0`). This is the set forwarded to Layer 2.
   *
   * IMPORTANT (Part C.4): unreachable targets (`executed === 0`) are NEVER
   * `passedLayer1` — failure is not a pass. For runs with coverage gaps
   * (`outcome === 'passed-with-gaps'`), `passedLayer1` remains true but
   * consumers MUST inspect `stats.notExecuted`/`outcome` before treating the
   * result as fully clean.
   */
  passedLayer1: boolean;
  findings: Finding[];
  results: Layer1ProbeResult[];
  stats: Layer1Stats;
}

export interface Layer1RunnerOptions {
  /** Set of probes to run. Defaults to `LAYER1_PROBES`. */
  probes?: readonly StaticProbe[];
  /** Optional stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

/** Maximum length of `evidence.output` to keep findings size-bounded. */
const EVIDENCE_OUTPUT_MAX = 8_000;

function buildEvidence(
  probe: StaticProbe,
  outputContent: string,
  detection: { rationale: string; matched?: string },
  responseMetadata: Record<string, string> | undefined,
): Evidence {
  const truncated = outputContent.length > EVIDENCE_OUTPUT_MAX;
  const output = truncated ? `${outputContent.slice(0, EVIDENCE_OUTPUT_MAX)}…` : outputContent;

  const metadata: Record<string, string> = {
    probeId: probe.id,
    technique: probe.technique,
    detection: detection.rationale,
  };
  if (detection.matched !== undefined) {
    metadata.matched = detection.matched;
  }
  if (truncated) {
    metadata.outputTruncated = 'true';
  }
  // Target response context (e.g. model, finishReason) is useful in reports.
  if (responseMetadata !== undefined) {
    for (const [key, value] of Object.entries(responseMetadata)) {
      metadata[`target_${key}`] = value;
    }
  }

  return {
    input: probe.input.payload,
    output,
    metadata,
  };
}

/**
 * Run Layer 1 probes against `target`. Probes are executed sequentially
 * (Layer 1 is cheap; sequential execution avoids overwhelming the target).
 * Each `Finding` is Zod-validated before being returned.
 */
export async function runLayer1Probes(
  target: ScanTarget,
  options: Layer1RunnerOptions = {},
): Promise<Layer1Report> {
  const probes = options.probes ?? LAYER1_PROBES;
  const results: Layer1ProbeResult[] = [];
  const findings: Finding[] = [];

  emitProgress(options.onProgress, {
    phase: 'layer-1',
    status: 'started',
    message: `Running Layer 1 static probes (${probes.length})`,
    detail: { probes: probes.length },
  });

  for (const probe of probes) {
    let response: TargetResponse;
    try {
      response = await target.send(probe.input);
    } catch (error) {
      if (error instanceof TargetAdapterError) {
        // Target unreachable → probe did NOT execute. Not a "pass".
        results.push({
          probeId: probe.id,
          technique: probe.technique,
          category: probe.category,
          status: 'not-executed',
          rationale: 'Probe did not execute: target adapter failed to respond.',
          error: error.message,
        });
        continue;
      }
      // Unexpected error (e.g. detector/internal bug) is NOT a target failure —
      // do not swallow it as "not-executed" (CLAUDE.md §3). Let it propagate.
      throw error;
    }

    const detection = probe.detect(response);
    if (!detection.detected) {
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'clean',
        rationale: detection.rationale,
      });
      continue;
    }

    const finding = findingSchema.parse({
      id: `layer1:${probe.id}`,
      severity: probe.severity,
      category: probe.category,
      title: probe.title,
      description: probe.description,
      evidence: buildEvidence(
        probe,
        response.content,
        { rationale: detection.rationale, ...(detection.matched !== undefined ? { matched: detection.matched } : {}) },
        response.metadata,
      ),
      recommendation: probe.recommendation,
    });
    findings.push(finding);
    results.push({
      probeId: probe.id,
      technique: probe.technique,
      category: probe.category,
      status: 'detected',
      rationale: detection.rationale,
      finding,
    });
  }

  const stats = summarize(results);
  const outcome = deriveOutcome(stats);

  emitProgress(options.onProgress, {
    phase: 'layer-1',
    status: 'completed',
    message: `Layer 1 complete: ${findings.length} finding(s), outcome ${outcome}`,
    detail: { findings: findings.length, executed: stats.executed, outcome },
  });

  return {
    outcome,
    passedLayer1: stats.detected === 0 && stats.executed > 0,
    findings,
    results,
    stats,
  };
}

function summarize(results: readonly Layer1ProbeResult[]): Layer1Stats {
  let detected = 0;
  let clean = 0;
  let notExecuted = 0;
  for (const result of results) {
    if (result.status === 'detected') {
      detected += 1;
    } else if (result.status === 'clean') {
      clean += 1;
    } else {
      notExecuted += 1;
    }
  }
  return {
    total: results.length,
    executed: detected + clean,
    detected,
    clean,
    notExecuted,
  };
}

function deriveOutcome(stats: Layer1Stats): Layer1Outcome {
  if (stats.detected > 0) {
    return 'vulnerable';
  }
  if (stats.executed === 0) {
    // Zero findings but no probe executed → target unreachable,
    // NOT clean. (Part C.4: failure is not a pass.)
    return 'target-unreachable';
  }
  if (stats.notExecuted > 0) {
    return 'passed-with-gaps';
  }
  return 'passed';
}
