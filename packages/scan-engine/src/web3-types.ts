import { z } from 'zod';

import type { Web3Chain } from './config';

/**
 * Web3 wire types shared across L1 + L2 + L3 (Sprint A3, T-A3.2).
 *
 * The Web3 scan splits into two engine interfaces (founder-confirmed in T-A3.1):
 *  - `Web3DAppTarget` (extends `PageContext`) owns L1 (wallet interaction) and L2
 *    (dApp frontend/infrastructure) — same loaded Playwright page, two probe
 *    families sharing one data source.
 *  - `OnChainContextProvider` owns L3 (on-chain context) — a separate side
 *    channel against read-only RPC + explorer APIs (concrete implementations
 *    land in T-A3.4 once the founder confirms RPC/explorer provider choice).
 *
 * These shared types are referenced by both halves: addresses harvested from L1
 * intercepted requests become L3 inputs; the chain selected for L3 is the same
 * `chain` that L1 reports to the dApp via the synthetic provider.
 *
 * Trust boundary (CLAUDE.md §3): every shape that crosses out of the page
 * (intercepted wallet requests, harvested contract addresses) carries a Zod
 * schema; consumers `parse` before use — the DOM is untrusted external data
 * just like an LLM response or an API body. The schemas here are the source
 * of truth.
 */

/**
 * A 20-byte EVM address as the canonical lower-cased `0x`-prefixed hex string.
 * Stored lower-cased so de-duplication is purely string equality; the engine
 * does not depend on EIP-55 checksum casing (we re-checksum at the UI layer
 * if needed).
 */
export const contractAddressSchema = z
  .string()
  .regex(/^0x[0-9a-f]{40}$/i, 'invalid EVM address')
  .transform((value) => value.toLowerCase() as `0x${string}`);

export type ContractAddress = z.infer<typeof contractAddressSchema>;

/**
 * The full EIP-1193 method surface the synthetic provider recognises (T-A3.2).
 * The list reflects what real dApps actually call across modern wallet flows
 * (MetaMask, RainbowKit, Web3Modal). Methods outside this list are still
 * recorded — the provider records EVERY call, even unrecognised ones — but
 * are returned as a JSON-RPC "Method not supported" error (EIP-1193 code
 * 4200) so the dApp sees the same failure surface a real wallet would emit
 * for an unknown method.
 *
 * Recognised here, with the wallet-attack relevance per probe family:
 *  - connection: `eth_requestAccounts`, `eth_accounts`, `eth_chainId`,
 *    `net_version`, `wallet_requestPermissions`, `wallet_getPermissions` —
 *    needed so dApps complete their wallet-detection flow at all.
 *  - state read (kept truthful + cheap): `eth_getBalance`, `eth_blockNumber`,
 *    `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_estimateGas`,
 *    `eth_feeHistory`, `eth_call`.
 *  - sign / send (the L1 probe surface): `eth_sendTransaction`,
 *    `eth_signTypedData_v4`, `eth_signTypedData_v3`, `eth_signTypedData`,
 *    `eth_signTypedData_v1`, `personal_sign`, `eth_sign`,
 *    `wallet_sendCalls` (EIP-5792 batch send), `wallet_signCalls`.
 *  - chain / asset management (the L1 cross-chain probe surface):
 *    `wallet_switchEthereumChain`, `wallet_addEthereumChain`,
 *    `wallet_watchAsset`, `wallet_getCapabilities`.
 *
 * EIP-7702 SetCode delegation is detected from `eth_sendTransaction` params
 * carrying an `authorizationList` (transaction type `0x04` per EIP-7702),
 * not from a separate method name — so it does not need its own enum value
 * here; the L1 probe inspects the params shape.
 */
export const walletRequestMethodSchema = z.string().min(1);

/**
 * One EIP-1193 `request({ method, params })` call intercepted by the synthetic
 * provider. The `params` shape varies per method and is therefore captured as
 * raw JSON (`z.unknown()`); the L1 probes (T-A3.3) parse method-specific
 * shapes themselves when they need to. `timestamp` is `Date.now()` from the
 * page side — purely informational; do not depend on it for security
 * decisions (a hostile page can hand-set it). `sequence` is the monotonic
 * order in which the synthetic provider observed calls and IS reliable
 * (assigned by the provider stub, not by the caller).
 */
export const walletRequestSchema = z.object({
  sequence: z.number().int().nonnegative(),
  method: walletRequestMethodSchema,
  /** JSON-RPC params as the dApp passed them. Shape varies per method. */
  params: z.unknown(),
  timestamp: z.number().int().nonnegative(),
  /** Method-specific outcome: what the synthetic provider returned (`resolved`)
   * or rejected with (`rejected`). The L1 probes inspect this to detect, e.g.,
   * a `wallet_switchEthereumChain` the dApp issued and the synthetic provider
   * accepted (so the dApp now believes it is on a different chain). */
  outcome: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('resolved'), result: z.unknown() }),
    z.object({ kind: z.literal('rejected'), errorCode: z.number().int(), errorMessage: z.string() }),
  ]),
});

export type WalletRequest = z.infer<typeof walletRequestSchema>;

/** A reference to a contract address discovered during L1. Carries the
 * provenance (which intercepted call, or the DOM) so L3 probes and the report
 * can explain WHY the address was scanned. */
export const referencedContractSchema = z.object({
  address: contractAddressSchema,
  /** How this address was first observed:
   *  - `wallet-request`: appeared in an intercepted EIP-1193 request (`to`
   *    in `eth_sendTransaction`/`eth_call`, `verifyingContract` in EIP-712
   *    typed data, the spender in a Permit2 / `approve` payload, etc).
   *  - `dom-reference`: matched the EVM-address regex inside the rendered
   *    HTML (button data attrs, URL path segments, embedded ABIs). Weaker
   *    signal — many DOMs include explorer links — but worth scanning.
   */
  origin: z.enum(['wallet-request', 'dom-reference']),
  /** The `sequence` index of the wallet request that surfaced this address,
   * present iff `origin === 'wallet-request'`. */
  walletRequestSequence: z.number().int().nonnegative().optional(),
  /** The wallet-request method that surfaced this address (`eth_sendTransaction`
   * etc.), present iff `origin === 'wallet-request'`. */
  walletRequestMethod: walletRequestMethodSchema.optional(),
});

export type ReferencedContract = z.infer<typeof referencedContractSchema>;

/**
 * The L1 capture result harvested off the page after navigation (and an
 * optional Connect-button drive). Validated with this schema before any L1
 * probe consumes it — the page DOM is untrusted external data.
 */
export const web3CaptureSchema = z.object({
  walletRequests: z.array(walletRequestSchema),
  referencedContracts: z.array(referencedContractSchema),
  /** True when the harvester observed at least one wallet request. False is
   * the honest "no interactive flow observed" signal — the L1 runner emits
   * the corresponding coverage gap in that case. */
  observedInteractiveFlow: z.boolean(),
});

export type Web3Capture = z.infer<typeof web3CaptureSchema>;

/** EVM chain id (hex `0x…` string) for a `Web3Chain`. Reported to the dApp
 * via `eth_chainId` and `net_version`; matched by the L1
 * `mismatched-chainid-request` probe (a dApp requesting a chain different
 * from the configured one — phishing pattern). */
export function chainIdHex(chain: Web3Chain): `0x${string}` {
  switch (chain) {
    case 'ethereum':
      return '0x1'; // 1
    case 'base':
      return '0x2105'; // 8453
  }
}

/** Decimal chain id as a string, for `net_version` (legacy method dApps still
 * call to ask "what network are we on" in decimal). */
export function chainIdDecimal(chain: Web3Chain): string {
  switch (chain) {
    case 'ethereum':
      return '1';
    case 'base':
      return '8453';
  }
}
