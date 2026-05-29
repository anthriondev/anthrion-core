import type { OwaspWeb3Category } from './category';
import { findingSchema, type Evidence, type Finding } from './finding';
import { emitProgress, type ScanProgressCallback } from './progress';
import { WEB3_L2_PROBES } from './web3-l2-probes';
import type { Web3L2CoverageNote, Web3L2Detection, Web3L2Probe } from './web3-l2-probe';
import type { Web3DAppTarget } from './web3-target';
import type { Web3Chain } from './config';

/**
 * Web3 L2 runner (Sprint A3, T-A3.6).
 *
 * Drives the curated `WEB3_L2_PROBES` against a `Web3DAppTarget` and
 * produces a normalised `Web3L2Report`. Mirrors the L1 / L3 / api-scan
 * honesty rules:
 *
 *  - A probe that times out is `not-executed`, never `clean`.
 *  - A probe that throws an unexpected error is `not-executed`, captured
 *    as an error message — NEVER silently swallowed into "safe".
 *  - Per-probe coverage notes (sub-checks the probe could NOT perform)
 *    surface in `coverageNotes[]`. NOT findings — honest declarations
 *    that part of the indicator surface wasn't inspected (e.g. DNSSEC
 *    validation, CDN bundle-drift fetch failures).
 *  - Empty `detections` AND no coverage notes from a probe = real "clean"
 *    on this target (nothing to flag, every sub-check completed).
 *
 * Findings are stable per (probeId, subjectKey):
 *   per-resource (SRI absent on script X, blocklist match on host Y) →
 *     `${probeId}#subject=${subjectKey}`
 *   target-level (DNS NS lookup failed, no per-resource subject) →
 *     `${probeId}#target`
 */

export type Web3L2ProbeStatus = 'detected' | 'clean' | 'not-executed';

export interface Web3L2ProbeResult {
  probeId: string;
  technique: string;
  category: OwaspWeb3Category;
  status: Web3L2ProbeStatus;
  /** Explanation of the decision, or the reason the probe did not execute. */
  rationale: string;
  /** Normalised findings — present iff `status === 'detected'`. */
  findings: Finding[];
  /** Honest sub-check skips collected by the probe — present even when
   * `status === 'clean'` (a clean detection can still have coverage notes). */
  coverageNotes: Web3L2CoverageNote[];
  /** Error / timeout message — present iff `status === 'not-executed'`. */
  error?: string;
}

/**
 * Summary outcome of an L2 run:
 *  - `vulnerable`         — ≥1 probe detection.
 *  - `passed`             — every probe executed, zero detections, no
 *                           per-probe coverage notes anywhere — the ONLY
 *                           outcome that means "we looked at everything and
 *                           found nothing."
 *  - `passed-with-gaps`   — no detections, but ≥1 probe did not execute
 *                           OR ≥1 probe surfaced a coverage note. NOT a
 *                           clean bill.
 */
export type Web3L2Outcome = 'vulnerable' | 'passed' | 'passed-with-gaps';

export interface Web3L2Stats {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
  /** Total count of coverage notes across all probes. */
  coverageNoteCount: number;
}

export interface Web3L2Report {
  chain: Web3Chain;
  outcome: Web3L2Outcome;
  findings: Finding[];
  results: Web3L2ProbeResult[];
  /** Flat list of every coverage note any probe surfaced — duplicated from
   * the per-probe results for easy report-side consumption. */
  coverageNotes: Web3L2CoverageNote[];
  stats: Web3L2Stats;
}

export interface RunWeb3L2Options {
  /** Per-probe timeout (ms). L2 probes can perform small outbound calls
   * (CDN double-fetch, DNS NS lookup) so the cap needs headroom; the bundle-
   * drift sub-check is the worst case (two HTTP GETs per pinned-CDN script). */
  probeTimeoutMs?: number;
  /** Override the curated probe set (tests / specialised scans). */
  probes?: readonly Web3L2Probe[];
  /** Stage-level progress sink (T4.2). */
  onProgress?: ScanProgressCallback;
}

/** Default per-probe timeout. Generous — accommodates double-fetch on
 * multiple pinned-CDN scripts + DNS round-trip. */
export const DEFAULT_WEB3_L2_PROBE_TIMEOUT_MS = 60_000;

class ProbeTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProbeTimeoutError';
  }
}

function withTimeout<T>(ms: number, label: string, op: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new ProbeTimeoutError(`${label}: timed out after ${ms}ms`)),
      ms,
    );
    op.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

/**
 * Run the curated `WEB3_L2_PROBES` (or `options.probes`) against `target`.
 */
export async function runWeb3Layer2(
  target: Web3DAppTarget,
  options: RunWeb3L2Options = {},
): Promise<Web3L2Report> {
  const probes = options.probes ?? WEB3_L2_PROBES;
  const probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_WEB3_L2_PROBE_TIMEOUT_MS;
  const onProgress = options.onProgress;

  emitProgress(onProgress, {
    phase: 'web3-l2',
    status: 'started',
    message: `Web3 L2 (frontend/infrastructure) started — ${probes.length} probe${probes.length === 1 ? '' : 's'}, chain=${target.chain}`,
    detail: { probes: probes.length, chain: target.chain },
  });

  const results: Web3L2ProbeResult[] = [];
  const findings: Finding[] = [];
  const allCoverageNotes: Web3L2CoverageNote[] = [];

  for (const probe of probes) {
    let evaluation;
    try {
      evaluation = await withTimeout(
        probeTimeoutMs,
        probe.id,
        Promise.resolve(probe.evaluate(target)),
      );
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : `probe failed: ${String(cause)}`;
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'not-executed',
        rationale: `Probe ${probe.id} did not execute: ${message}`,
        findings: [],
        coverageNotes: [],
        error: message,
      });
      continue;
    }

    const probeCoverageNotes = [...(evaluation.coverageNotes ?? [])];
    allCoverageNotes.push(...probeCoverageNotes);

    if (evaluation.detections.length === 0) {
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'clean',
        rationale: probeCoverageNotes.length > 0
          ? `${probe.technique} did not detect ${probe.category}; ${probeCoverageNotes.length} sub-check coverage note(s) surfaced.`
          : `${probe.technique} did not detect ${probe.category} and every sub-check completed.`,
        findings: [],
        coverageNotes: probeCoverageNotes,
      });
      continue;
    }

    const probeFindings: Finding[] = [];
    for (const detection of evaluation.detections) {
      const finding = detectionToFinding(probe, detection);
      probeFindings.push(finding);
      findings.push(finding);
    }
    results.push({
      probeId: probe.id,
      technique: probe.technique,
      category: probe.category,
      status: 'detected',
      rationale:
        probeFindings.length === 1
          ? (evaluation.detections[0]?.rationale ?? probe.description)
          : `${probe.technique} produced ${probeFindings.length} finding${probeFindings.length === 1 ? '' : 's'}.`,
      findings: probeFindings,
      coverageNotes: probeCoverageNotes,
    });
  }

  const stats: Web3L2Stats = {
    total: results.length,
    executed: results.filter((r) => r.status !== 'not-executed').length,
    detected: results.filter((r) => r.status === 'detected').length,
    clean: results.filter((r) => r.status === 'clean').length,
    notExecuted: results.filter((r) => r.status === 'not-executed').length,
    coverageNoteCount: allCoverageNotes.length,
  };

  const outcome: Web3L2Outcome =
    stats.detected > 0
      ? 'vulnerable'
      : stats.notExecuted > 0 || stats.coverageNoteCount > 0
        ? 'passed-with-gaps'
        : 'passed';

  emitProgress(onProgress, {
    phase: 'web3-l2',
    status: 'completed',
    message: `Web3 L2: ${outcome} (${stats.detected} detected / ${stats.clean} clean / ${stats.notExecuted} not-executed; ${stats.coverageNoteCount} coverage note${stats.coverageNoteCount === 1 ? '' : 's'})`,
    detail: {
      outcome,
      detected: stats.detected,
      clean: stats.clean,
      notExecuted: stats.notExecuted,
      coverageNotes: stats.coverageNoteCount,
      findings: findings.length,
    },
  });

  return {
    chain: target.chain,
    outcome,
    findings,
    results,
    coverageNotes: allCoverageNotes,
    stats,
  };
}

function detectionToFinding(probe: Web3L2Probe, detection: Web3L2Detection): Finding {
  const evidence: Evidence = {
    input: detection.subjectKey !== undefined
      ? `${probe.technique} on ${detection.subjectKey}`
      : `${probe.technique} on target`,
    output: detection.evidence,
    ...(detection.metadata !== undefined ? { metadata: detection.metadata } : {}),
  };

  const id = detection.subjectKey !== undefined
    ? `${probe.id}#subject=${detection.subjectKey}`
    : `${probe.id}#target`;

  return findingSchema.parse({
    id,
    severity: detection.severity ?? probe.severity,
    category: probe.category,
    title: probe.title,
    description: detection.description ?? probe.description,
    evidence,
    recommendation: probe.recommendation,
  });
}
