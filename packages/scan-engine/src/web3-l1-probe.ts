import { z } from 'zod';

import type { OwaspWeb3Category } from './category';
import type { Severity } from './severity';
import type { Web3DAppTarget } from './web3-target';
import type { WalletRequest } from './web3-types';

/**
 * Web3 L1 — wallet-interaction probe abstraction (Sprint A3, T-A3.3).
 *
 * Probes consume the `WalletRequest[]` captured by the synthetic EIP-1193
 * provider (T-A3.2) and decide whether any intercepted request matches an
 * approval-phishing pattern from OWASP Web3 WA06. The contract mirrors
 * `ApiProbe` (T-A1.2): probes never branch on transport (Playwright vs Node
 * stub), one probe per L1 slug from `owaspWeb3CategorySchema`, no LLM, no
 * network — pure structural inspection of intercepted JSON-RPC payloads.
 *
 * Severity calibration (rubric §10/§11/§12 + WA06 reference):
 *  - **Critical** for EIP-7702 SetCode delegation. Novel enough that any
 *    detection warrants top severity — accepting one of these hands the dApp
 *    permanent on-chain bytecode control of the EOA until revoked.
 *  - **High** for wallet-approval-phishing (unlimited token allowances),
 *    permit2-mass-approval, and mismatched-chainid-request. These are
 *    well-established WA06 patterns with concrete fund-loss outcomes.
 *  - **Medium** for deceptive-typed-data-signature and personal-sign smell.
 *    Both are structural smells about *how* something is being signed, not
 *    proof that the signed object is malicious. The "indicator-not-verdict"
 *    wording rule from T-FIX.6 / T-A3.5 applies here too.
 *
 * Probes MUST NOT throw under normal "I checked and didn't find anything" —
 * return `NO_L1_DETECTIONS` instead. THROW only for genuine probe-internal
 * failure; the runner marks the probe `not-executed` in that case, NEVER
 * "safe" (api-scan honesty rule).
 */

/** Outcome of one probe against the target. Carries the `WalletRequest.sequence`
 * of the offending request so the report can point at exactly which intercepted
 * call triggered the finding. */
export interface Web3L1Detection {
  /**
   * Sequence index of the `WalletRequest` that triggered detection — every L1
   * detection MUST be tied to a specific intercepted request. The runner uses
   * this to build a stable per-detection `Finding.id`.
   */
  walletRequestSequence: number;
  /** The method on the offending wallet request (`eth_sendTransaction` etc.).
   * Mirrored in evidence + finding id. */
  walletRequestMethod: string;
  /** Explanation of the positive decision. ALWAYS populated. */
  rationale: string;
  /** Observed value(s) that triggered detection — becomes evidence.output. */
  evidence: string;
  /** Optional extra metadata for the Finding evidence. Truncated at the
   * detection boundary — never carry an unbounded params blob. */
  metadata?: Record<string, string>;
  /** Optional severity override for context-dependent findings. Falls back to
   * `probe.severity` when absent. */
  severity?: Severity;
  /** Optional description override when the same probe has materially
   * different failure modes. Falls back to `probe.description`. */
  description?: string;
}

/** A single Web3 L1 probe. */
export interface Web3L1Probe {
  /** Stable probe id. Prefix `web3:l1:` keeps it distinct from `api:` / `web:` /
   * the AI scan layer 1 ids. */
  id: string;
  /** Short technique label for evidence / report. */
  technique: string;
  /** OWASP Web3 category of the Finding produced by this probe. MUST be one of
   * the six L1 slugs from `owaspWeb3CategorySchema`. */
  category: OwaspWeb3Category;
  /** Default severity if the probe triggers (may be overridden per detection). */
  severity: Severity;
  /** Concise Finding title. */
  title: string;
  /** Description of the vulnerability being tested. */
  description: string;
  /** Basic mitigation recommendation. */
  recommendation: string;
  /** Run the probe over the target's captured wallet requests. Returns 0..N
   * detections. */
  evaluate(target: Web3DAppTarget): Promise<readonly Web3L1Detection[]>;
}

/** Convenience: empty-detections result with no allocation. */
export const NO_L1_DETECTIONS: readonly Web3L1Detection[] = Object.freeze([]);

// ── Schema helpers used in tests ────────────────────────────────────────────

export const web3L1DetectionSchema = z.object({
  walletRequestSequence: z.number().int().nonnegative(),
  walletRequestMethod: z.string().min(1),
  rationale: z.string().min(1),
  evidence: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
  severity: z.unknown().optional(),
  description: z.string().optional(),
});

// ── Wallet-request payload helpers (used by every probe) ────────────────────

/** Lower-cased canonical Permit2 contract address (Uniswap, deployed at the
 * same address on every EVM chain Permit2 supports). Used by the Permit2
 * probe to recognise direct calls into Permit2 regardless of chain. */
export const PERMIT2_CONTRACT_ADDRESS = '0x000000000022d473030f116ddee9f6b43ac78ba3';

/** Max-value sentinel for `uint256` allowances (`2**256 - 1`), lower-cased.
 * 64 hex characters of `f`. */
export const MAX_UINT256_HEX_LOWER = 'f'.repeat(64);

/** Max-value sentinel for Permit2's `uint160` allowance amount (`2**160 - 1`),
 * lower-cased. Permit2's `approve` amount field is `uint160`, so the "unlimited"
 * Permit2 grant is `2**160 - 1`, NOT `2**256 - 1`. */
export const MAX_UINT160_HEX_LOWER = 'f'.repeat(40);

/** ERC-20 `approve(address,uint256)` 4-byte function selector. */
export const SELECTOR_ERC20_APPROVE = '0x095ea7b3';

/** ERC-721 / ERC-1155 `setApprovalForAll(address,bool)` 4-byte function
 * selector. Identical across both token standards. */
export const SELECTOR_SET_APPROVAL_FOR_ALL = '0xa22cb465';

/** Strip the `0x` prefix from a hex string and lower-case the rest. Returns
 * `undefined` if the input is not a valid `0x`-prefixed hex string. */
function normaliseHex(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  if (!value.startsWith('0x') && !value.startsWith('0X')) return undefined;
  const body = value.slice(2);
  if (!/^[0-9a-fA-F]*$/.test(body)) return undefined;
  return body.toLowerCase();
}

/** Read a plain-object slot if `obj` is a non-null plain object. Returns
 * `undefined` for non-objects, missing fields, or non-string values when
 * `as` is `'string'`. Generic over `as: 'any'` for caller-side narrowing. */
export function readField(obj: unknown, field: string): unknown {
  if (obj === null || typeof obj !== 'object') return undefined;
  return (obj as Record<string, unknown>)[field];
}

/** First element of an array, or `undefined` if the input is not an array or
 * is empty. The wrapper avoids `params[0]!` non-null assertions in callers. */
export function firstParam(params: unknown): unknown {
  if (!Array.isArray(params)) return params;
  return params.length > 0 ? params[0] : undefined;
}

/** Truncate a string for inclusion in evidence — guards against unbounded
 * params blobs ending up in the report. Mirrors `EVIDENCE_SNIPPET_MAX`'s
 * conservative ceiling (safety.ts) without importing it here. */
export const EVIDENCE_VALUE_MAX = 400;

export function clipForEvidence(value: string): string {
  if (value.length <= EVIDENCE_VALUE_MAX) return value;
  return `${value.slice(0, EVIDENCE_VALUE_MAX - 3)}...`;
}

/**
 * Decode an ERC-20 `approve(address,uint256)` call from `eth_sendTransaction`
 * calldata. Returns `undefined` if the data does not start with the approve
 * selector or has the wrong length. The amount is returned as a lower-case
 * 64-character hex string (no `0x` prefix) so callers can compare against
 * `MAX_UINT256_HEX_LOWER` directly.
 *
 * Calldata layout: `0x` + 4-byte selector + 32-byte spender (right-padded,
 * the address occupies the low 20 bytes) + 32-byte amount. Total length:
 * 2 + 8 + 64 + 64 = 138 chars.
 */
export interface DecodedApprove {
  /** Lower-case `0x`-prefixed spender address. */
  spender: `0x${string}`;
  /** Lower-case 64-char hex amount, no prefix. */
  amountHex: string;
}

export function decodeErc20Approve(data: unknown): DecodedApprove | undefined {
  const hex = normaliseHex(data);
  if (hex === undefined) return undefined;
  if (hex.length !== 4 * 2 + 32 * 2 + 32 * 2) return undefined;
  if (`0x${hex.slice(0, 8)}` !== SELECTOR_ERC20_APPROVE) return undefined;
  const spenderField = hex.slice(8, 8 + 64);
  // Right-aligned address: last 40 hex chars of the 64-char field. The high
  // 24 bytes must be zero for a well-formed address parameter, but we accept
  // any value (some malformed callers don't pad; we extract conservatively).
  const spender = `0x${spenderField.slice(-40)}` as `0x${string}`;
  const amountHex = hex.slice(8 + 64);
  return { spender, amountHex };
}

/**
 * Decode an ERC-721 / ERC-1155 `setApprovalForAll(address,bool)` call. Returns
 * `undefined` if the data does not match. The boolean is encoded in the last
 * 32 bytes; we treat any non-zero value as `true`, matching Solidity's `bool`
 * decoding semantics (anything non-zero is true).
 */
export interface DecodedSetApprovalForAll {
  operator: `0x${string}`;
  approved: boolean;
}

export function decodeSetApprovalForAll(
  data: unknown,
): DecodedSetApprovalForAll | undefined {
  const hex = normaliseHex(data);
  if (hex === undefined) return undefined;
  if (hex.length !== 4 * 2 + 32 * 2 + 32 * 2) return undefined;
  if (`0x${hex.slice(0, 8)}` !== SELECTOR_SET_APPROVAL_FOR_ALL) return undefined;
  const operatorField = hex.slice(8, 8 + 64);
  const operator = `0x${operatorField.slice(-40)}` as `0x${string}`;
  const approvedField = hex.slice(8 + 64);
  // Any non-zero value in the bool slot decodes to true.
  const approved = /[1-9a-f]/.test(approvedField);
  return { operator, approved };
}

/**
 * Decode the typed-data argument of `eth_signTypedData_*`. Returns the parsed
 * object (or `undefined` if missing/malformed). Real dApps pass the typed data
 * either as a JS object or as a JSON string; both shapes are handled. The
 * returned object is **NOT validated against EIP-712 structure** — that's the
 * job of each probe, since each probe cares about a different field subset.
 */
export function decodeTypedDataPayload(req: WalletRequest): Record<string, unknown> | undefined {
  if (!req.method.startsWith('eth_signTypedData')) return undefined;
  // EIP-712 calls pass [signer, typedData]; legacy v1 passes [params, signer].
  // We handle both by trying [0] then [1] for a parseable object.
  const params = req.params;
  if (!Array.isArray(params)) return undefined;
  for (const candidate of params) {
    const parsed = tryParseTypedDataValue(candidate);
    if (parsed !== undefined) return parsed;
  }
  return undefined;
}

function tryParseTypedDataValue(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === 'string') {
    try {
      const parsed: unknown = JSON.parse(value);
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** Compare two hex chain ids regardless of casing / `0x` prefix presence /
 * leading zero padding. `0x1`, `0x01`, `0X1`, `1` all match. */
export function hexChainEquals(a: string, b: string): boolean {
  const aNorm = a.toLowerCase().replace(/^0x/, '').replace(/^0+/, '') || '0';
  const bNorm = b.toLowerCase().replace(/^0x/, '').replace(/^0+/, '') || '0';
  return aNorm === bNorm;
}

/** Compare a chain id from typed data (which can be a number, decimal string,
 * or hex string) against a decimal chain id from the target config. */
export function chainIdMatches(
  rawValueFromRequest: unknown,
  expectedDecimal: string,
): boolean {
  if (typeof rawValueFromRequest === 'number' && Number.isFinite(rawValueFromRequest)) {
    return String(rawValueFromRequest) === expectedDecimal;
  }
  if (typeof rawValueFromRequest === 'string') {
    const trimmed = rawValueFromRequest.trim();
    if (trimmed === '') return false;
    if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
      // Hex form; convert to decimal for compare via BigInt.
      try {
        return BigInt(trimmed).toString() === expectedDecimal;
      } catch {
        return false;
      }
    }
    return trimmed === expectedDecimal;
  }
  return false;
}
