import type { OwaspWeb3Category } from './category';
import { findingSchema, type Evidence, type Finding } from './finding';
import type { Severity } from './severity';
import { emitProgress, type ScanProgressCallback } from './progress';
import type { Web3Chain } from './config';
import type { OnChainContext, OnChainContextProvider } from './web3-onchain-context';
import type { ContractAddress, ReferencedContract } from './web3-types';
import { WEB3_L3_PROBES } from './web3-l3-probes';
import {
  elevateOneTierCapHigh,
  maxSeverity,
  type Web3L3Detection,
  type Web3L3Probe,
} from './web3-l3-probe';

/**
 * Web3 L3 runner (Sprint A3, T-A3.5).
 *
 * Drives the curated `WEB3_L3_PROBES` against the on-chain context fetched
 * by the T-A3.4 loader for every referenced contract address, then composes
 * the hybrid aggregate `elevated-risk-contract` finding per the §4
 * composition decision: per-indicator findings are RETAINED, AND when ≥2
 * indicators hit on the same contract, ONE additional aggregate finding is
 * emitted whose severity is `max(individual indicators) + 1 tier, capped at
 * High`. Critical is reserved for individual L1 probes that warrant it
 * directly (e.g. `eip-7702-set-code-delegation`) and is NEVER synthesised
 * from aggregation. Aggregate evidence explicitly lists the contributing
 * indicator slugs — the elevation is auditable, not hidden composite math.
 *
 * Honesty rules (mirror api-scan / web3-l1):
 *  - A probe that times out is `not-executed`, never `clean`.
 *  - A probe that throws an unexpected error is `not-executed`, captured as
 *    an error message, NEVER silently swallowed into "safe".
 *  - When the loader cannot fetch context for an address (`context.availability
 *    === 'unavailable'`), per-probe results for that address are `not-executed`
 *    with a "context unavailable" reason and the address is recorded under
 *    `addressCoverageGaps` with the slug `web3-l3-on-chain-context-unavailable`.
 *    A scan with partial L3 is still a real scan; a crashed L3 would silently
 *    zero its coverage — same anti-pattern Phase 1 prohibits elsewhere.
 *  - When NO addresses were observed at all, the outcome is
 *    `no-contracts-observed` (the L1 capture had no contract references). L3
 *    cannot probe what no one named; the report surfaces this honestly.
 *
 * Each `Finding` is Zod-validated before leaving the engine
 * (ARCHITECTURE.md §4.4). Findings are stable per (probeId, address) so a
 * second scan of the same dApp lines up cleanly:
 *   per-indicator id  = `${probeId}#address=${address}`
 *   aggregate id      = `web3:l3:elevated-risk-contract#address=${address}`
 */

export type Web3L3ProbeStatus = 'detected' | 'clean' | 'not-executed';

export interface Web3L3ProbeResult {
  probeId: string;
  technique: string;
  category: OwaspWeb3Category;
  /** Address this result applies to. Each (probe, address) pair gets its own
   * result so the report can show "probe X was clean on address A but
   * not-executed on address B". */
  address: ContractAddress;
  status: Web3L3ProbeStatus;
  /** Explanation of the decision, or the reason the probe did not execute. */
  rationale: string;
  /** Normalised findings — present iff `status === 'detected'`. */
  findings: Finding[];
  /** Error / timeout / context-unavailability message — present iff
   * `status === 'not-executed'`. */
  error?: string;
}

/**
 * Summary outcome of an L3 run:
 *  - `vulnerable`            — ≥1 probe×address detection.
 *  - `passed`                — every (probe, address) executed and produced
 *                              zero findings; the ONLY outcome that means
 *                              "we looked and found nothing".
 *  - `passed-with-gaps`      — no findings but ≥1 (probe, address) did not
 *                              execute. NOT a clean bill.
 *  - `no-contracts-observed` — input contract list was empty. L3 cannot probe
 *                              what no one named; the report surfaces this.
 */
export type Web3L3Outcome =
  | 'vulnerable'
  | 'passed'
  | 'passed-with-gaps'
  | 'no-contracts-observed';

export interface Web3L3Stats {
  /** Number of probe×address pairs evaluated (`probes.length *
   * contracts.length`, or 0 if no contracts were observed). */
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
  /** Number of unique addresses the runner saw. */
  addressCount: number;
  /** Number of unique addresses whose context was unavailable — drives
   * `addressCoverageGaps`. */
  unavailableAddressCount: number;
  /** Per-contract aggregate `elevated-risk-contract` findings emitted by the
   * hybrid composer. Subset of `detected`. */
  aggregateFindingCount: number;
}

/** A coverage gap for one address whose context the loader could not fetch.
 * The slug stays the single source of truth in `WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND`. */
export interface Web3L3AddressCoverageGap {
  address: ContractAddress;
  /** Stable kind slug — same string for every per-address gap. The worker
   * (T-A3.7) materialises this into a `coverageGap` object against the
   * shared schema; renaming requires updating both sides deliberately. */
  kind: typeof WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND;
  /** Honest reason the loader returned with the context. Never carries
   * provider API keys (sub-agent rubric §12). */
  reason: string;
}

export interface Web3L3Report {
  chain: Web3Chain;
  outcome: Web3L3Outcome;
  findings: Finding[];
  results: Web3L3ProbeResult[];
  /** Per-address coverage gaps when the loader returned `unavailable`. */
  addressCoverageGaps: Web3L3AddressCoverageGap[];
  stats: Web3L3Stats;
}

export interface RunWeb3L3Options {
  /** Per-probe timeout (ms). Most L3 probes are pure function-of-context, so
   * the only thing this cap protects against is a future probe that takes
   * unbounded compute on pathological inputs. */
  probeTimeoutMs?: number;
  /** Override the curated probe set (tests / specialised scans). */
  probes?: readonly Web3L3Probe[];
  /** Stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

/** Default per-probe timeout. L3 probes do not network round-trip — context
 * is already fetched — so 10s is a generous cap. */
export const DEFAULT_WEB3_L3_PROBE_TIMEOUT_MS = 10_000;

/** The single-source-of-truth coverage gap slug for per-address loader
 * failures. The worker (T-A3.7) materialises this into a `coverageGap`
 * object against the shared schema; the engine does NOT import the shared
 * schema (scan-engine is PURE — no cross-package dependencies). Tests check
 * the slug here so renames cannot silently desync from the worker side. */
export const WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND = 'web3-l3-on-chain-context-unavailable';

/** The slug the aggregate `elevated-risk-contract` finding carries.
 * Re-exported here so the runner's composition logic and tests can reference
 * a single constant rather than the bare string literal. */
export const WEB3_L3_ELEVATED_RISK_CATEGORY: OwaspWeb3Category = 'elevated-risk-contract';

/** The aggregate finding id prefix — paired with `#address=` + the contract
 * address to form a stable per-contract id. */
export const WEB3_L3_ELEVATED_RISK_ID_PREFIX = 'web3:l3:elevated-risk-contract';

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
 * Run the curated `WEB3_L3_PROBES` (or `options.probes`) across the
 * referenced contracts.
 *
 * Behavior:
 *  1. De-duplicate the input contracts by lower-cased address; the harvester
 *     should already produce unique addresses but the runner re-checks
 *     defensively (a hostile DOM could surface duplicates).
 *  2. For each address, ask the provider for context (the provider never
 *     throws; failures are encoded in `availability`). If
 *     `availability === 'unavailable'`, every probe for THIS address is
 *     `not-executed` and the address joins `addressCoverageGaps`.
 *  3. For each available context, run every probe under a per-probe timeout
 *     and convert detections to Zod-validated `Finding`s.
 *  4. Per-contract hybrid aggregate composition: when ≥2 probes produced ≥1
 *     detection each on the SAME address, emit ONE additional
 *     `elevated-risk-contract` finding whose severity is
 *     `elevateOneTierCapHigh(max(individual indicator severities))`. Evidence
 *     lists the contributing indicator slugs explicitly.
 */
export async function runWeb3Layer3(
  contracts: readonly ReferencedContract[],
  provider: OnChainContextProvider,
  options: RunWeb3L3Options = {},
): Promise<Web3L3Report> {
  const probes = options.probes ?? WEB3_L3_PROBES;
  const probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_WEB3_L3_PROBE_TIMEOUT_MS;
  const onProgress = options.onProgress;

  const uniqueAddresses = dedupeAddresses(contracts);

  emitProgress(onProgress, {
    phase: 'web3-l3',
    status: 'started',
    message: `Web3 L3 (on-chain context) started — ${probes.length} probe${probes.length === 1 ? '' : 's'}, ${uniqueAddresses.length} unique address${uniqueAddresses.length === 1 ? '' : 'es'}, chain=${provider.chain}`,
    detail: {
      probes: probes.length,
      addresses: uniqueAddresses.length,
      chain: provider.chain,
    },
  });

  if (uniqueAddresses.length === 0) {
    emitProgress(onProgress, {
      phase: 'web3-l3',
      status: 'completed',
      message: 'Web3 L3: no contracts observed — runner had nothing to probe',
      detail: { outcome: 'no-contracts-observed' },
    });
    return {
      chain: provider.chain,
      outcome: 'no-contracts-observed',
      findings: [],
      results: [],
      addressCoverageGaps: [],
      stats: {
        total: 0,
        executed: 0,
        detected: 0,
        clean: 0,
        notExecuted: 0,
        addressCount: 0,
        unavailableAddressCount: 0,
        aggregateFindingCount: 0,
      },
    };
  }

  const results: Web3L3ProbeResult[] = [];
  const findings: Finding[] = [];
  const addressCoverageGaps: Web3L3AddressCoverageGap[] = [];
  let aggregateFindingCount = 0;

  for (const address of uniqueAddresses) {
    const context = await provider.getContractContext(address);

    if (context.availability === 'unavailable') {
      const reason = context.unavailableReason ?? 'on-chain context unavailable';
      addressCoverageGaps.push({
        address,
        kind: WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND,
        reason,
      });
      for (const probe of probes) {
        results.push({
          probeId: probe.id,
          technique: probe.technique,
          category: probe.category,
          address,
          status: 'not-executed',
          rationale: `Probe ${probe.id} did not execute for ${address}: ${reason}`,
          findings: [],
          error: reason,
        });
      }
      continue;
    }

    // Per-address detection accumulator for hybrid aggregate composition.
    const perAddressContributors: Array<{
      probeId: string;
      slug: OwaspWeb3Category;
      severity: Severity;
    }> = [];

    for (const probe of probes) {
      let detections: readonly Web3L3Detection[];
      try {
        detections = await withTimeout(
          probeTimeoutMs,
          `${probe.id}@${address}`,
          Promise.resolve(probe.evaluate(context)),
        );
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : `probe failed: ${String(cause)}`;
        results.push({
          probeId: probe.id,
          technique: probe.technique,
          category: probe.category,
          address,
          status: 'not-executed',
          rationale: `Probe ${probe.id} did not execute for ${address}: ${message}`,
          findings: [],
          error: message,
        });
        continue;
      }

      if (detections.length === 0) {
        results.push({
          probeId: probe.id,
          technique: probe.technique,
          category: probe.category,
          address,
          status: 'clean',
          rationale: `${probe.technique} did not detect ${probe.category} on ${address}.`,
          findings: [],
        });
        continue;
      }

      const probeFindings: Finding[] = [];
      for (const detection of detections) {
        const finding = detectionToFinding(probe, detection);
        probeFindings.push(finding);
        findings.push(finding);
        perAddressContributors.push({
          probeId: probe.id,
          slug: probe.category,
          severity: finding.severity,
        });
      }
      results.push({
        probeId: probe.id,
        technique: probe.technique,
        category: probe.category,
        address,
        status: 'detected',
        rationale:
          probeFindings.length === 1
            ? (detections[0]?.rationale ?? probe.description)
            : `${probe.technique} produced ${probeFindings.length} findings on ${address}.`,
        findings: probeFindings,
      });
    }

    // Hybrid aggregate composition (T-A3.5 §4): emit `elevated-risk-contract`
    // when ≥2 DISTINCT indicator slugs triggered on this address. We dedupe
    // by slug so a probe that emits multiple detections of the same indicator
    // (currently none, but defensive) counts as one contributing indicator.
    const distinctSlugs = new Set(perAddressContributors.map((c) => c.slug));
    if (distinctSlugs.size >= 2) {
      const aggregate = composeAggregateFinding(address, provider.chain, perAddressContributors);
      findings.push(aggregate);
      aggregateFindingCount += 1;
    }
  }

  const stats: Web3L3Stats = {
    total: results.length,
    executed: results.filter((r) => r.status !== 'not-executed').length,
    detected: results.filter((r) => r.status === 'detected').length,
    clean: results.filter((r) => r.status === 'clean').length,
    notExecuted: results.filter((r) => r.status === 'not-executed').length,
    addressCount: uniqueAddresses.length,
    unavailableAddressCount: addressCoverageGaps.length,
    aggregateFindingCount,
  };

  const outcome: Web3L3Outcome =
    stats.detected > 0 ? 'vulnerable' : stats.notExecuted > 0 ? 'passed-with-gaps' : 'passed';

  emitProgress(onProgress, {
    phase: 'web3-l3',
    status: 'completed',
    message: `Web3 L3: ${outcome} (${stats.detected} detected / ${stats.clean} clean / ${stats.notExecuted} not-executed across ${stats.addressCount} address${stats.addressCount === 1 ? '' : 'es'}; ${stats.aggregateFindingCount} aggregate)`,
    detail: {
      outcome,
      detected: stats.detected,
      clean: stats.clean,
      notExecuted: stats.notExecuted,
      addresses: stats.addressCount,
      unavailableAddresses: stats.unavailableAddressCount,
      aggregateFindings: stats.aggregateFindingCount,
      findings: findings.length,
    },
  });

  return {
    chain: provider.chain,
    outcome,
    findings,
    results,
    addressCoverageGaps,
    stats,
  };
}

/** De-duplicate referenced contracts by lower-cased address. Preserves
 * first-seen order so the report reads deterministically for a given
 * harvester output. */
function dedupeAddresses(contracts: readonly ReferencedContract[]): ContractAddress[] {
  const seen = new Set<string>();
  const out: ContractAddress[] = [];
  for (const c of contracts) {
    const key = c.address.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c.address);
  }
  return out;
}

function detectionToFinding(probe: Web3L3Probe, detection: Web3L3Detection): Finding {
  const evidence: Evidence = {
    input: `${probe.technique} on contract ${detection.address}`,
    output: detection.evidence,
    ...(detection.metadata !== undefined ? { metadata: detection.metadata } : {}),
  };

  const id = `${probe.id}#address=${detection.address}`;

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

/**
 * Compose the per-contract aggregate `elevated-risk-contract` finding.
 *
 * Severity: `max(contributors.severity)` elevated by one tier and capped at
 * High (`elevateOneTierCapHigh`). Critical is NEVER synthesised — reserved
 * for L1 probes that warrant it directly.
 *
 * Evidence: lists the contributing indicator slugs in `evidence.output` so
 * the elevation is auditable from the finding alone. Per the T-A3.5 §4
 * decision: "no hidden composite math."
 */
function composeAggregateFinding(
  address: ContractAddress,
  chain: Web3Chain,
  contributors: ReadonlyArray<{ probeId: string; slug: OwaspWeb3Category; severity: Severity }>,
): Finding {
  // De-duplicate the slug list (defensive — a single probe could in principle
  // emit multiple detections, all of the same slug) while preserving the order
  // contributors were observed in.
  const seenSlugs = new Set<OwaspWeb3Category>();
  const slugsInOrder: OwaspWeb3Category[] = [];
  for (const c of contributors) {
    if (seenSlugs.has(c.slug)) continue;
    seenSlugs.add(c.slug);
    slugsInOrder.push(c.slug);
  }

  // Max of contributors' severities, then elevate one tier with the cap.
  // Seed with the least-severe slot ("Info") so the reducer always lands on a
  // real contributor value (every L3 probe returns severities >= Low).
  const baseSeverity: Severity = contributors.reduce<Severity>(
    (acc, c) => maxSeverity(acc, c.severity),
    'Info',
  );
  const elevated = elevateOneTierCapHigh(baseSeverity);

  const evidence: Evidence = {
    input: `L3 indicator aggregation on contract ${address} (chain=${chain})`,
    output: `indicators present: ${slugsInOrder.join(', ')}`,
    metadata: {
      address,
      chain,
      indicatorCount: String(slugsInOrder.length),
      indicators: slugsInOrder.join(','),
      baseSeverity,
      elevatedSeverity: elevated,
    },
  };

  return findingSchema.parse({
    id: `${WEB3_L3_ELEVATED_RISK_ID_PREFIX}#address=${address}`,
    severity: elevated,
    category: WEB3_L3_ELEVATED_RISK_CATEGORY,
    title: 'Contract shows multiple risk indicators on-chain',
    description:
      `Multiple independent L3 indicators flagged this contract during the on-chain context check: ${slugsInOrder.join(', ')}. ` +
      'Each indicator on its own is a signal warranting caution rather than proof of malice; together they describe a contract that combines several of the user-protection patterns Phase 1 calls out (unverified source, opaque proxy implementation, single-key admin, fresh deployment, look-alike token name). This is an indicator-based aggregation, not a composite verdict — the contributing slugs are listed in evidence so the elevation is auditable.',
    evidence,
    recommendation:
      'Review each contributing indicator above before taking action. Avoid granting unlimited allowances to contracts that combine multiple of these signals; verify the contract address and project legitimacy via independent channels (project docs, second block explorer, audit reports) before signing.',
  });
}
