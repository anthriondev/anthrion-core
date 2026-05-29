import { z } from 'zod';

import type { Web3Chain } from './config';
import { contractAddressSchema, type ContractAddress } from './web3-types';

/**
 * On-chain context provider interface (Sprint A3, T-A3.2 surface — concrete
 * implementations land in T-A3.4 once the founder confirms RPC + explorer
 * provider choice).
 *
 * Founder-confirmed in T-A3.1: L3 lives on a separate side channel from L1/L2
 * — a different mechanic (read-only RPC + explorer HTTP) with a different
 * failure mode (provider outage / rate limit) than the Playwright-driven L1/L2.
 *
 * SAFETY RULE (sub-agent rubric §11): read-only operations only. Concrete
 * implementations MUST use only EVM read methods (`eth_getCode`,
 * `eth_getStorageAt`, `eth_call`) and explorer GET endpoints. No
 * `eth_sendRawTransaction`, no signing, no private keys, no wallet of any
 * kind. There is no transaction broadcast path in this scan family.
 *
 * SAFETY RULE (sub-agent rubric §12): RPC / explorer API keys MUST NOT appear
 * in any `Finding`, evidence string, PDF, UI text, or log line. The
 * `OnChainContext` shape below carries no `apiKey` slot for that reason; key
 * handling is internal to the concrete implementation.
 *
 * HONESTY RULE: a provider hiccup (rate limit, outage, malformed response)
 * MUST NOT crash a Web3 scan. The provider returns an `OnChainContext` with
 * `availability !== 'complete'` and a non-empty `unavailableReason`; the L3
 * runner then emits the `web3-l3-on-chain-context-unavailable` coverage gap
 * for that address. A scan with partial L3 is still a real scan; a crashed
 * L3 would silently zero its coverage, which is the same anti-pattern Phase
 * 1 prohibits for any other layer.
 */
export interface OnChainContextProvider {
  readonly chain: Web3Chain;
  /**
   * Resolve on-chain context for `address`. ALWAYS returns an
   * `OnChainContext` — never throws on a provider failure (the failure is
   * encoded in `availability` + `unavailableReason`). Implementations cache
   * per-scan so the same address requested twice is one round-trip.
   */
  getContractContext(address: ContractAddress): Promise<OnChainContext>;
}

/**
 * Whether the address looks like a contract from the chain's perspective.
 *  - `contract` — `eth_getCode` returned non-empty bytecode.
 *  - `eoa` — `eth_getCode` returned `0x` (externally-owned account).
 *  - `unknown` — `eth_getCode` failed; could be either.
 */
export const addressKindSchema = z.enum(['contract', 'eoa', 'unknown']);
export type AddressKind = z.infer<typeof addressKindSchema>;

/**
 * Proxy structure for an EIP-1967 / OpenZeppelin proxy contract. Detection
 * reads two fixed storage slots:
 *  - `0x360894…7bbc` (EIP-1967 implementation slot)
 *  - `0xb53127…6103` (EIP-1967 admin slot)
 * `implementation` / `admin` are null when the proxy slot is empty (i.e.
 * not a proxy in that pattern). A proxy with both slots null but a custom
 * pattern (legacy OpenZeppelin, custom diamond) reports `null` here — the
 * L3 probe surfaces "proxy detection inconclusive" rather than claiming
 * "not a proxy".
 */
export const proxyContextSchema = z.object({
  isProxy: z.boolean(),
  implementation: contractAddressSchema.nullable(),
  admin: contractAddressSchema.nullable(),
});

export type ProxyContext = z.infer<typeof proxyContextSchema>;

/**
 * Admin / owner role surface. The L3 probe inspects this to flag the
 * `eoa-admin-single-key` indicator: a single EOA holding owner privileges
 * over the contract can sign upgrades alone, with no multisig delay.
 *
 *  - `owner` — the `owner()` accessor return; null when the contract does
 *    not expose `owner()`.
 *  - `pendingOwner` — the `pendingOwner()` accessor return (Ownable2Step
 *    pattern); null when absent.
 *  - `ownerKind` — classification of `owner`:
 *      `eoa` — `owner` resolves to an externally-owned account
 *      `contract` — `owner` resolves to a contract (likely multisig or timelock)
 *      `not-exposed` — `owner()` is not callable on this contract
 *      `unknown` — the lookup failed before resolution
 */
export const adminRoleContextSchema = z.object({
  owner: contractAddressSchema.nullable(),
  pendingOwner: contractAddressSchema.nullable(),
  ownerKind: z.enum(['eoa', 'contract', 'not-exposed', 'unknown']),
});

export type AdminRoleContext = z.infer<typeof adminRoleContextSchema>;

/**
 * Explorer-reported metadata. All nullable individually — an explorer can
 * answer "verified yes" while not knowing the deployer address, for example.
 */
export const explorerMetadataSchema = z.object({
  sourceVerified: z.boolean().nullable(),
  contractName: z.string().nullable(),
  compilerVersion: z.string().nullable(),
  deployerAddress: contractAddressSchema.nullable(),
  deploymentTxHash: z.string().nullable(),
  /** Unix seconds. Null when the explorer does not expose deployment time. */
  deploymentTimestamp: z.number().int().nonnegative().nullable(),
});

export type ExplorerMetadata = z.infer<typeof explorerMetadataSchema>;

/**
 * Overall availability of the resolved context — drives the L3 coverage gap.
 *  - `complete` — every sub-channel (RPC code, RPC storage, RPC call,
 *    explorer) returned a result.
 *  - `partial` — at least one sub-channel returned a result and at least one
 *    sub-channel failed.
 *  - `unavailable` — every sub-channel failed; the address could not be
 *    inspected at all (e.g. RPC provider down + explorer down).
 */
export const contextAvailabilitySchema = z.enum(['complete', 'partial', 'unavailable']);
export type ContextAvailability = z.infer<typeof contextAvailabilitySchema>;

export const onChainContextSchema = z.object({
  address: contractAddressSchema,
  chain: z.enum(['ethereum', 'base']),
  kind: addressKindSchema,
  proxy: proxyContextSchema.nullable(),
  admin: adminRoleContextSchema.nullable(),
  explorer: explorerMetadataSchema.nullable(),
  availability: contextAvailabilitySchema,
  /** Non-empty iff `availability !== 'complete'`. Honest description of what
   * the provider could not fetch (used by the L3 coverage gap; MUST NOT
   * contain provider API keys or URLs — sub-agent rubric §12). */
  unavailableReason: z.string().nullable(),
});

export type OnChainContext = z.infer<typeof onChainContextSchema>;
