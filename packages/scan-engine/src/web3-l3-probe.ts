import { z } from 'zod';

import type { OwaspWeb3Category } from './category';
import type { Severity } from './severity';
import { SEVERITY_ORDER } from './severity';
import type { ContractAddress } from './web3-types';
import type { OnChainContext } from './web3-onchain-context';

/**
 * Web3 L3 — on-chain context probe abstraction (Sprint A3, T-A3.5).
 *
 * L3 probes consume the resolved `OnChainContext` for a single contract
 * address (verified-source status, proxy structure, owner role surface,
 * explorer metadata — produced by the T-A3.4 loader) and decide whether the
 * contract exhibits an indicator from OWASP SC01 / SC10 / WA10. The contract
 * mirrors `Web3L1Probe` (T-A3.3) and `ApiProbe` (T-A1.2): one probe per L3
 * slug from `owaspWeb3CategorySchema`, no LLM, no network — pure structural
 * inspection of the already-fetched context.
 *
 * Severity is INDICATOR LANGUAGE, not VERDICT LANGUAGE (T-FIX.6 wording rule
 * surfaced again in the T-A3.5 spec): an unverified contract or an EOA-admin
 * is a real risk signal warranting user caution, not proof of malice. The
 * description / rationale strings each probe ships read accordingly — the
 * report must never claim "this contract is malicious because <indicator>",
 * only "<indicator> is present; here is what it means."
 *
 * Calibration (T-A3.5 spec):
 *  - **Low/Medium** for `contract-source-not-verified` — Low for an old
 *    unverified contract (verification can lag legitimately for years); the
 *    indicator escalates to Medium when the contract is also young or has the
 *    structural shape of a fresh deployment. NEVER Critical alone (false-
 *    positive risk: a popular contract is sometimes "unverified-elsewhere"
 *    while verified on another explorer the scan didn't consult).
 *  - **Medium-High** for `proxy-without-verified-implementation` — Medium for
 *    a beacon/legacy proxy whose implementation is *unknown*; High when the
 *    implementation address resolved but its source is unverified (the user is
 *    approving upgradeable logic they cannot read).
 *  - **Medium-High** for `eoa-admin-single-key` — Medium when an EOA holds
 *    `owner()` on a contract that does NOT also look "fresh" or unverified;
 *    High when the EOA owner is combined with a fresh deployment or
 *    unverified source (the upgrade path has no time-lock and the code is
 *    opaque).
 *  - **Medium** for `recent-contract-deployment` (default cutoff: 72h) — flat;
 *    "young" doesn't prove malice, only warrants user awareness. Probes that
 *    cannot determine the deployment age return no detection rather than
 *    inventing one.
 *  - **High** for `token-impersonation-indicator` (WA10) — when a contract
 *    bears the *name* of a canonical token (USDC, USDT, DAI, WETH) at a
 *    *different* address from the canonical one on the same chain. This is
 *    the single L3 indicator the report is allowed to phrase strongly because
 *    the name collision is verifiable, not heuristic.
 *
 * No probe in this layer EVER emits Critical: the aggregate composer (T-A3.5
 * §4 hybrid composition) explicitly caps its elevated severity at High, and
 * Critical is reserved for L1 probes that warrant it directly
 * (`eip-7702-set-code-delegation`).
 *
 * Probes MUST NOT throw under normal "I checked and the indicator isn't
 * present" — return `NO_L3_DETECTIONS` instead. THROW only for genuine
 * probe-internal failure; the runner marks the probe `not-executed` in that
 * case, NEVER "safe".
 */

/** Outcome of one probe against a single contract's on-chain context.
 * Carries the address so the runner can build a stable per-detection
 * `Finding.id` and the aggregate composer can group detections by contract. */
export interface Web3L3Detection {
  /** The contract address the detection pertains to. Lower-cased. */
  address: ContractAddress;
  /** Explanation of the positive decision. ALWAYS populated. */
  rationale: string;
  /** Observed value(s) that triggered detection — becomes evidence.output. */
  evidence: string;
  /** Optional extra metadata for the Finding evidence. Truncated at the
   * detection boundary — never carry a full explorer/RPC payload. */
  metadata?: Record<string, string>;
  /** Optional severity override for context-dependent findings (e.g. an
   * EOA-admin indicator climbs from Medium → High when combined with an
   * unverified source on the same contract). Falls back to `probe.severity`. */
  severity?: Severity;
  /** Optional description override when the same probe has materially
   * different failure modes. Falls back to `probe.description`. */
  description?: string;
}

/** A single Web3 L3 probe. */
export interface Web3L3Probe {
  /** Stable probe id. Prefix `web3:l3:` keeps it distinct from `web3:l1:` /
   * `api:` / `web:` ids. */
  id: string;
  /** Short technique label for evidence / report. */
  technique: string;
  /** OWASP Web3 category of the Finding produced by this probe. MUST be one
   * of the L3 (non-aggregate) slugs from `owaspWeb3CategorySchema`. */
  category: OwaspWeb3Category;
  /** Default severity if the probe triggers (may be overridden per detection). */
  severity: Severity;
  /** Concise Finding title. */
  title: string;
  /** Description of the indicator. Indicator-not-verdict wording rule
   * applies — read as "this signal is present; here is why it warrants
   * caution," NOT as "this contract is malicious." */
  description: string;
  /** Basic mitigation recommendation — user-facing, addressed to the dApp
   * user (not the contract author): how to act on the indicator. */
  recommendation: string;
  /** Inspect one contract's on-chain context and return 0..N detections
   * (most L3 probes emit 0 or 1 per call; only the structurally combined
   * probes may emit >1). MUST tolerate partial contexts: a missing explorer
   * record or missing admin role means the probe RETURNS NO DETECTION for
   * that input, not that it invents a finding. */
  evaluate(context: OnChainContext): Promise<readonly Web3L3Detection[]> | readonly Web3L3Detection[];
}

/** Convenience: empty-detections result with no allocation. */
export const NO_L3_DETECTIONS: readonly Web3L3Detection[] = Object.freeze([]);

// ── Schema helpers used in tests ────────────────────────────────────────────

export const web3L3DetectionSchema = z.object({
  address: z.string().min(1),
  rationale: z.string().min(1),
  evidence: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
  severity: z.unknown().optional(),
  description: z.string().optional(),
});

// ── Shared constants / helpers used by the curated probe set ────────────────

/** Default cutoff for `recent-contract-deployment`. The spec calls out 72h as
 * the calibration target; exposed as a constant so tests and the worker can
 * reference the same value without duplicating it. */
export const DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS = 72 * 60 * 60;

/** Lower-bound stale-record cutoff used by the `contract-source-not-verified`
 * severity decision. A contract older than this — by the explorer's
 * deployment timestamp — is treated as "old unverified" (Low). Anything
 * younger or unknown is "fresh unverified" (Medium). The 180-day window is a
 * conservative midpoint between "deployed yesterday" and "deployed years ago";
 * documented here rather than hard-coded so the calibration is visible. */
export const STALE_DEPLOYMENT_AGE_SECONDS = 180 * 24 * 60 * 60;

/**
 * Tiny curated registry of well-known fungible tokens used by the
 * `token-impersonation-indicator` (WA10) probe. The probe flags a contract
 * whose explorer-reported `contractName` matches a registered token's
 * canonical name on the same chain BUT whose own address differs from the
 * canonical address. The list is intentionally small and bundled in-repo
 * (sub-agent rubric §11 — read-only, no network) and a real Phase-1.5 scope:
 * USDC / USDT / DAI / WETH cover the four highest-volume impersonation
 * targets on Ethereum + Base. Expansion lives in a later sprint; the probe is
 * honest about its small surface and does NOT emit "this isn't impersonated"
 * negative findings — silence is silence.
 *
 * Names are stored upper-case to match how explorers report `contractName`
 * for the canonical contracts; the probe normalises the explorer value to
 * upper-case before comparing.
 */
export interface WellKnownToken {
  /** Canonical token name as exposed by the explorer's verified record. */
  name: string;
  /** Lower-cased canonical address on each supported chain. A token that
   * does not exist on a chain (e.g. WETH on Base in a deprecated form) is
   * simply absent from that chain's slot. */
  byChain: Readonly<Partial<Record<'ethereum' | 'base', string>>>;
}

export const WELL_KNOWN_TOKEN_REGISTRY: readonly WellKnownToken[] = Object.freeze([
  {
    name: 'USDC',
    byChain: {
      ethereum: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
      base: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    },
  },
  {
    name: 'USDT',
    byChain: {
      ethereum: '0xdac17f958d2ee523a2206206994597c13d831ec7',
      // Native USDT was not deployed on Base in Phase 1.5 — slot is intentionally absent.
    },
  },
  {
    name: 'DAI',
    byChain: {
      ethereum: '0x6b175474e89094c44da98b954eedeac495271d0f',
      base: '0x50c5725949a6f0c72e6c4a641f24049a917db0cb',
    },
  },
  {
    name: 'WETH',
    byChain: {
      ethereum: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
      base: '0x4200000000000000000000000000000000000006',
    },
  },
]);

/** Truncate a string for inclusion in evidence — mirrors the L1 cap so a
 * pathological explorer response can't bloat the report. */
export const EVIDENCE_VALUE_MAX = 400;

export function clipForEvidence(value: string): string {
  if (value.length <= EVIDENCE_VALUE_MAX) return value;
  return `${value.slice(0, EVIDENCE_VALUE_MAX - 3)}...`;
}

/**
 * Elevate a severity by exactly one tier and cap the result at `High`.
 *
 * Used by the L3 aggregate composer (T-A3.5 §4 hybrid composition): when ≥2
 * indicators hit on the same contract, the synthesised `elevated-risk-contract`
 * Finding takes `max(individual indicators) + 1 tier, capped at High`. Critical
 * is reserved for individual probes that warrant it directly (e.g. L1's
 * `eip-7702-set-code-delegation`) and is NEVER produced by aggregation.
 *
 * Examples (using `SEVERITY_ORDER` = [Critical, High, Medium, Low, Info]):
 *   Info → Low; Low → Medium; Medium → High; High → High (cap);
 *   Critical → High (defensive cap — no L3 probe emits Critical, so this
 *   branch only fires if a future probe is added that does).
 */
export function elevateOneTierCapHigh(severity: Severity): Severity {
  const idx = SEVERITY_ORDER.indexOf(severity);
  // SEVERITY_ORDER is sorted most-severe → least-severe, so "more severe"
  // means a *smaller* index. One tier more severe → idx - 1; clamp at 0.
  const elevatedIdx = Math.max(idx - 1, 0);
  const elevated = SEVERITY_ORDER[elevatedIdx];
  // Defensive: cap at High; never synthesise Critical from aggregation.
  if (elevated === 'Critical') return 'High';
  // SEVERITY_ORDER is non-empty and `elevatedIdx` is in-bounds, so
  // `elevated` is always defined; narrow for the type checker.
  return elevated ?? severity;
}

/** Return the more-severe of two severities. Used by the aggregate composer to
 * compute `max(individual indicators)` before elevation. */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b;
}
