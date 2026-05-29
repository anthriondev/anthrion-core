import type { OwaspWeb3Category } from './category';
import { findingSchema, type Evidence, type Finding } from './finding';
import { emitProgress, type ScanProgressCallback } from './progress';
import { WEB3_L1_PROBES } from './web3-l1-probes';
import type { Web3L1Detection, Web3L1Probe } from './web3-l1-probe';
import type { Web3DAppTarget } from './web3-target';
import type { Web3Chain } from './config';

/**
 * Web3 L1 runner (Sprint A3, T-A3.3).
 *
 * Drives the curated `WEB3_L1_PROBES` against a `Web3DAppTarget` (T-A3.2) and
 * produces a normalised `Web3L1Report`. The runner mirrors the api-scan and
 * web-scan runners' honesty rules — a probe that times out or throws is
 * `not-executed`, never "clean" — plus one rule specific to L1:
 *
 *  - **No interactive flow observed → coverage gap, NOT a clean bill.**
 *    L1 can only probe what the dApp asked the wallet for. A dApp that gates
 *    every wallet call behind a Connect-button click might not have been
 *    driven deep enough for any request to be intercepted, and the runner
 *    cannot tell that case apart from "the dApp has no wallet interaction at
 *    all" from inside L1 itself. Both surface honestly as
 *    `outcome === 'no-interactive-flow-observed'`, and the worker (T-A3.7)
 *    translates that into the
 *    `web3-l1-no-interactive-flow-observed` coverage gap that the report
 *    eventually carries (the `coverageGapKind` constant exported here is the
 *    single source of truth for the slug).
 *
 * The runner emits `Finding`s validated against the shared `findingSchema`
 * before they leave the engine (ARCHITECTURE.md §4.4). Findings are stable
 * per offending wallet request — id is `${probeId}#seq=${sequence}` so a
 * report comparing two scans of the same dApp lines up cleanly.
 */

export type Web3L1ProbeStatus = 'detected' | 'clean' | 'not-executed';

export interface Web3L1ProbeResult {
  probeId: string;
  technique: string;
  category: OwaspWeb3Category;
  status: Web3L1ProbeStatus;
  /** Explanation of the decision, or the reason the probe did not execute. */
  rationale: string;
  /** Normalised findings — present iff `status === 'detected'`. */
  findings: Finding[];
  /** Error / timeout message — present iff `status === 'not-executed'`. */
  error?: string;
}

/**
 * Summary outcome of an L1 run:
 *  - `vulnerable`                  — ≥1 probe detected an issue.
 *  - `passed`                      — interactive flow observed AND every probe
 *                                    ran AND zero findings. The only outcome
 *                                    that means "we looked and found nothing."
 *  - `passed-with-gaps`            — interactive flow observed, no findings,
 *                                    but ≥1 probe did not execute. Coverage is
 *                                    incomplete → NOT a clean bill.
 *  - `no-interactive-flow-observed` — synthetic provider captured zero wallet
 *                                    requests. L1 cannot probe what the dApp
 *                                    did not ask for; the report surfaces the
 *                                    matching coverage gap. NOT "safe".
 */
export type Web3L1Outcome =
  | 'vulnerable'
  | 'passed'
  | 'passed-with-gaps'
  | 'no-interactive-flow-observed';

export interface Web3L1Stats {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
  /** Number of wallet requests captured by the synthetic provider. Zero is
   * the trigger for the no-interactive-flow outcome. */
  walletRequestCount: number;
}

export interface Web3L1Report {
  /** Chain the synthetic provider reported to the dApp during capture. */
  chain: Web3Chain;
  /** True iff the synthetic provider captured at least one wallet request.
   * False → outcome is `no-interactive-flow-observed`. */
  observedInteractiveFlow: boolean;
  outcome: Web3L1Outcome;
  findings: Finding[];
  results: Web3L1ProbeResult[];
  stats: Web3L1Stats;
}

export interface RunWeb3L1Options {
  /** Per-probe timeout (ms). A probe whose own logic hangs is cut. */
  probeTimeoutMs?: number;
  /** Override the curated probe set (tests / specialised scans). */
  probes?: readonly Web3L1Probe[];
  /** Stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

/**
 * Per-probe timeout, ms. L1 probes do not round-trip — they inspect a fixed,
 * already-captured request list — so the only thing this cap protects against
 * is pathologically large captured params blobs (DOM-injected by a hostile
 * page) sending a JSON.parse / regex into an unreasonable amount of work. 30s
 * is comfortable for normal flows and short enough that a stuck probe doesn't
 * stall a scan.
 */
export const DEFAULT_WEB3_L1_PROBE_TIMEOUT_MS = 30_000;

/**
 * The single-source-of-truth coverage gap slug emitted when no interactive
 * flow was observed during L1 capture. The worker (T-A3.7) materialises this
 * string into a `coverageGap` object against the shared `coverageGapKindSchema`;
 * the engine does not import the shared schema (scan-engine is PURE — no
 * cross-package dependencies). Tests check the slug here so renames cannot
 * silently desync from the worker side.
 */
export const WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND = 'web3-l1-no-interactive-flow-observed';

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
 * Run the curated `WEB3_L1_PROBES` (or `options.probes`) against `target`.
 *
 * Behavior:
 *  1. Read `target.observedInteractiveFlow()`. If `false`, every probe is
 *     marked `not-executed` with the no-interactive-flow rationale and the
 *     outcome is `no-interactive-flow-observed`. Probes are NOT run — there is
 *     nothing to inspect. This is the L1 honesty rule.
 *  2. Otherwise, each probe runs under a per-probe timeout. Detections are
 *     converted to Zod-validated `Finding`s with the probe's metadata. A probe
 *     that throws or times out is `not-executed`.
 */
export async function runWeb3Layer1(
  target: Web3DAppTarget,
  options: RunWeb3L1Options = {},
): Promise<Web3L1Report> {
  const probes = options.probes ?? WEB3_L1_PROBES;
  const probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_WEB3_L1_PROBE_TIMEOUT_MS;
  const onProgress = options.onProgress;

  emitProgress(onProgress, {
    phase: 'web3-l1',
    status: 'started',
    message: `Web3 L1 (wallet interaction) started — ${probes.length} probe${probes.length === 1 ? '' : 's'}, chain=${target.chain}`,
    detail: { probes: probes.length, chain: target.chain },
  });

  const walletRequests = await target.walletRequests();
  const observedInteractiveFlow = walletRequests.length > 0;

  if (!observedInteractiveFlow) {
    const notExecutedResults: Web3L1ProbeResult[] = probes.map((probe) =>
      buildNotExecutedResult(
        probe,
        'L1 captured zero wallet requests — no interactive flow observed.',
      ),
    );
    emitProgress(onProgress, {
      phase: 'web3-l1',
      status: 'completed',
      message: `Web3 L1: no interactive flow observed — coverage gap "${WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND}" applies`,
      detail: {
        outcome: 'no-interactive-flow-observed',
        walletRequestCount: 0,
        coverageGapKind: WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND,
      },
    });
    return {
      chain: target.chain,
      observedInteractiveFlow: false,
      outcome: 'no-interactive-flow-observed',
      findings: [],
      results: notExecutedResults,
      stats: {
        total: probes.length,
        executed: 0,
        detected: 0,
        clean: 0,
        notExecuted: probes.length,
        walletRequestCount: 0,
      },
    };
  }

  const results: Web3L1ProbeResult[] = [];
  const findings: Finding[] = [];
  for (const probe of probes) {
    let detections: readonly Web3L1Detection[];
    try {
      detections = await withTimeout(probeTimeoutMs, probe.id, probe.evaluate(target));
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : `probe failed: ${String(cause)}`;
      results.push(buildNotExecutedResult(probe, message));
      continue;
    }

    if (detections.length === 0) {
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        status: 'clean',
        rationale: `${probe.technique} did not detect ${probe.category} across ${walletRequests.length} intercepted wallet request${walletRequests.length === 1 ? '' : 's'}.`,
        findings: [],
      });
      continue;
    }

    const probeFindings: Finding[] = [];
    for (const detection of detections) {
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
          ? (detections[0]?.rationale ?? probe.description)
          : `${probe.technique} produced ${probeFindings.length} findings across ${walletRequests.length} intercepted wallet request${walletRequests.length === 1 ? '' : 's'}.`,
      findings: probeFindings,
    });
  }

  const stats: Web3L1Stats = {
    total: results.length,
    executed: results.filter((r) => r.status !== 'not-executed').length,
    detected: results.filter((r) => r.status === 'detected').length,
    clean: results.filter((r) => r.status === 'clean').length,
    notExecuted: results.filter((r) => r.status === 'not-executed').length,
    walletRequestCount: walletRequests.length,
  };

  const outcome: Web3L1Outcome =
    stats.detected > 0 ? 'vulnerable' : stats.notExecuted > 0 ? 'passed-with-gaps' : 'passed';

  emitProgress(onProgress, {
    phase: 'web3-l1',
    status: 'completed',
    message: `Web3 L1: ${outcome} (${stats.detected} detected / ${stats.clean} clean / ${stats.notExecuted} not-executed across ${walletRequests.length} intercepted request${walletRequests.length === 1 ? '' : 's'})`,
    detail: {
      outcome,
      detected: stats.detected,
      clean: stats.clean,
      notExecuted: stats.notExecuted,
      findings: findings.length,
      walletRequestCount: walletRequests.length,
    },
  });

  return {
    chain: target.chain,
    observedInteractiveFlow: true,
    outcome,
    findings,
    results,
    stats,
  };
}

function buildNotExecutedResult(probe: Web3L1Probe, error: string): Web3L1ProbeResult {
  return {
    probeId: probe.id,
    technique: probe.technique,
    category: probe.category,
    status: 'not-executed',
    rationale: `Probe ${probe.id} did not execute: ${error}`,
    findings: [],
    error,
  };
}

function detectionToFinding(probe: Web3L1Probe, detection: Web3L1Detection): Finding {
  const evidence: Evidence = {
    input: `${probe.technique} against ${detection.walletRequestMethod} (sequence ${detection.walletRequestSequence})`,
    output: detection.evidence,
    ...(detection.metadata !== undefined ? { metadata: detection.metadata } : {}),
  };

  const id = `${probe.id}#seq=${detection.walletRequestSequence}`;

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
