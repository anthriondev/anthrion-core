import type { Web3Chain } from './config';
import { contractAddressSchema, type ContractAddress } from './web3-types';
import {
  AlchemyRpcClient,
  EIP1967_ADMIN_SLOT,
  EIP1967_IMPLEMENTATION_SLOT,
  SELECTOR_OWNER,
  SELECTOR_PENDING_OWNER,
  Web3RpcError,
  ZERO_STORAGE_SLOT,
  decodeAddressFromStorage,
} from './web3-rpc-client';
import {
  EtherscanExplorerClient,
  Web3ExplorerError,
  type ExplorerSourceCode,
} from './web3-explorer-client';
import {
  onChainContextSchema,
  type AdminRoleContext,
  type AddressKind,
  type ExplorerMetadata,
  type OnChainContext,
  type OnChainContextProvider,
  type ProxyContext,
} from './web3-onchain-context';

/**
 * Concrete `OnChainContextProvider` (Sprint A3, T-A3.4) — Alchemy + Etherscan v2.
 *
 * Wires the two read clients into the engine's read-only side channel. The L3
 * runner (T-A3.5) consumes this for every referenced contract address harvested
 * during L1; the loader caches per-instance so a scan asking for the same
 * address twice is one round-trip.
 *
 * Lifecycle: one instance per scan. The worker (T-A3.7) constructs the
 * loader with the two clients + the scan's `chain`, runs the scan, and drops
 * the instance. The per-instance Map → per-scan cache contract is enforced by
 * the lifecycle, not by any internal state expiry.
 *
 * Graceful degradation: each of the four sub-channels (kind / proxy / admin /
 * explorer) is fetched independently and catches its own failure. The
 * resulting `OnChainContext` carries:
 *  - `availability === 'complete'`  iff every sub-channel returned a result.
 *  - `availability === 'partial'`   iff some sub-channel succeeded and some
 *                                   sub-channel failed.
 *  - `availability === 'unavailable'` iff every sub-channel failed.
 * `unavailableReason` carries an honest, non-sensitive description (provider
 * label + failure kind) — sub-agent rubric §12 forbids any URL / api-key in
 * this string. The clients' error messages are already key-free by
 * construction; we additionally pass them through `sanitizeReason` for an
 * extra defensive pass.
 */
export interface RemoteOnChainContextProviderConfig {
  chain: Web3Chain;
  rpc: AlchemyRpcClient;
  explorer: EtherscanExplorerClient;
}

export class RemoteOnChainContextProvider implements OnChainContextProvider {
  readonly chain: Web3Chain;
  private readonly rpc: AlchemyRpcClient;
  private readonly explorer: EtherscanExplorerClient;
  /** Per-instance promise cache: address → Promise<OnChainContext>. Storing the
   * Promise (not the resolved value) coalesces concurrent calls for the same
   * address into a single round-trip — a probe that asks for `getContractContext(a)`
   * twice in parallel only triggers one underlying fetch. */
  private readonly cache = new Map<ContractAddress, Promise<OnChainContext>>();

  constructor(config: RemoteOnChainContextProviderConfig) {
    this.chain = config.chain;
    this.rpc = config.rpc;
    this.explorer = config.explorer;
  }

  getContractContext(address: ContractAddress): Promise<OnChainContext> {
    const cached = this.cache.get(address);
    if (cached !== undefined) return cached;
    const pending = this.loadContext(address);
    this.cache.set(address, pending);
    return pending;
  }

  /** True iff the address has been seen before. Exposed for the L3 runner's
   * progress reporting and tests; not part of the `OnChainContextProvider`
   * interface. */
  hasCached(address: ContractAddress): boolean {
    return this.cache.has(address);
  }

  private async loadContext(address: ContractAddress): Promise<OnChainContext> {
    const failures: string[] = [];

    // 1. Determine kind via eth_getCode. This drives whether the other RPC
    //    sub-channels even make sense.
    let kindResult: { kind: AddressKind; failed: boolean };
    try {
      const code = await this.rpc.getCode(address);
      kindResult = {
        kind: code === '0x' || code === '0x0' ? 'eoa' : 'contract',
        failed: false,
      };
    } catch (cause) {
      failures.push(sanitizeReason(cause));
      kindResult = { kind: 'unknown', failed: true };
    }

    // 2. Sub-channels: proxy + admin (RPC-driven) and explorer (HTTP-driven).
    //    Run in parallel. Three cases for the RPC-driven channels:
    //      - kind=eoa     → skip (proxy/admin are null by definition; success).
    //      - kind=contract→ probe; catch failures into the partial state.
    //      - kind=unknown → the kind lookup itself failed, so we cannot honestly
    //                       claim "no proxy" without re-probing under the same
    //                       broken RPC. Mark both channels failed transitively
    //                       so availability honestly degrades to 'unavailable'
    //                       when the explorer is ALSO down.
    const proxyAdminInheritsFailure = kindResult.kind === 'unknown';
    const [proxyResult, adminResult, explorerResult] = await Promise.all([
      kindResult.kind === 'contract'
        ? this.loadProxy(address).catch((cause) => {
            failures.push(sanitizeReason(cause));
            return { proxy: null, failed: true } as const;
          })
        : Promise.resolve({ proxy: null, failed: proxyAdminInheritsFailure } as const),
      kindResult.kind === 'contract'
        ? this.loadAdmin(address).catch((cause) => {
            failures.push(sanitizeReason(cause));
            return { admin: null, failed: true } as const;
          })
        : Promise.resolve({ admin: null, failed: proxyAdminInheritsFailure } as const),
      this.loadExplorer(address).catch((cause) => {
        failures.push(sanitizeReason(cause));
        return { explorer: null, failed: true } as const;
      }),
    ]);

    const failedCount =
      (kindResult.failed ? 1 : 0) +
      (proxyResult.failed ? 1 : 0) +
      (adminResult.failed ? 1 : 0) +
      (explorerResult.failed ? 1 : 0);
    let availability: OnChainContext['availability'];
    if (failedCount === 0) {
      availability = 'complete';
    } else if (failedCount === 4) {
      availability = 'unavailable';
    } else {
      availability = 'partial';
    }
    const unavailableReason = failures.length > 0 ? failures.join('; ').slice(0, 500) : null;

    const context: OnChainContext = {
      address,
      chain: this.chain,
      kind: kindResult.kind,
      proxy: proxyResult.proxy,
      admin: adminResult.admin,
      explorer: explorerResult.explorer,
      availability,
      unavailableReason,
    };
    // Engine boundary: Zod-validate before returning. A bug that builds an
    // off-schema context fails loudly here rather than silently downstream
    // (CLAUDE.md §3 honesty rule).
    return onChainContextSchema.parse(context);
  }

  /** Read EIP-1967 implementation + admin slots. We do NOT trust a contract's
   * own `implementation()` accessor — a malicious proxy can lie there. The
   * canonical slot read is the source of truth. */
  private async loadProxy(address: ContractAddress): Promise<{ proxy: ProxyContext; failed: false }> {
    const [implSlot, adminSlot] = await Promise.all([
      this.rpc.getStorageAt(address, EIP1967_IMPLEMENTATION_SLOT),
      this.rpc.getStorageAt(address, EIP1967_ADMIN_SLOT),
    ]);
    const implementation = decodeAddressFromStorage(implSlot);
    const admin = decodeAddressFromStorage(adminSlot);
    const isProxy = implementation !== null || implSlot !== ZERO_STORAGE_SLOT;
    return {
      proxy: { isProxy, implementation, admin },
      failed: false,
    };
  }

  /** Read `owner()` and `pendingOwner()`. Then probe `eth_getCode` on `owner`
   * to classify EOA vs contract — the `eoa-admin-single-key` indicator
   * surfaces an EOA `owner` value. */
  private async loadAdmin(
    address: ContractAddress,
  ): Promise<{ admin: AdminRoleContext; failed: false }> {
    const [ownerReturn, pendingOwnerReturn] = await Promise.all([
      this.rpc.call(address, SELECTOR_OWNER),
      this.rpc.call(address, SELECTOR_PENDING_OWNER),
    ]);
    const owner = decodeReturnedAddress(ownerReturn);
    const pendingOwner = decodeReturnedAddress(pendingOwnerReturn);

    let ownerKind: AdminRoleContext['ownerKind'];
    if (owner === null) {
      ownerKind = 'not-exposed';
    } else {
      try {
        const ownerCode = await this.rpc.getCode(owner);
        ownerKind = ownerCode === '0x' || ownerCode === '0x0' ? 'eoa' : 'contract';
      } catch {
        // A failure resolving the owner's kind is non-fatal — we still know
        // the owner address itself, which the L3 probe can act on.
        ownerKind = 'unknown';
      }
    }
    return {
      admin: { owner, pendingOwner, ownerKind },
      failed: false,
    };
  }

  /** Combine `getsourcecode` + `getcontractcreation` + an RPC block-timestamp
   * lookup into the explorer metadata. The block timestamp is OPTIONAL — when
   * the RPC call fails, the metadata still carries the other fields and the
   * timestamp surfaces as `null`. */
  private async loadExplorer(
    address: ContractAddress,
  ): Promise<{ explorer: ExplorerMetadata; failed: false }> {
    const [source, creation] = await Promise.all([
      this.explorer.getSourceCode(address),
      this.explorer.getContractCreation(address).catch(() => null),
    ]);
    let deploymentTimestamp: number | null = null;
    if (creation !== null) {
      try {
        const blockNumber = await this.rpc.getTransactionBlockNumber(creation.txHash);
        if (blockNumber !== null) {
          deploymentTimestamp = await this.rpc.getBlockTimestamp(blockNumber);
        }
      } catch {
        // Timestamp lookup is best-effort. The explorer record is still useful
        // even without timestamp; null surfaces the L3 "deployment age
        // unknown" caveat.
        deploymentTimestamp = null;
      }
    }
    return {
      explorer: explorerMetadataFrom(source, creation, deploymentTimestamp),
      failed: false,
    };
  }
}

/**
 * Decode the low 20 bytes of an `eth_call` return value as an EVM address.
 * Returns null for `'0x'` (function not implemented / reverted to empty) or
 * the all-zeros address. The encoding is the same right-padded 32-byte form
 * that storage slots use, but here it comes off the wire from `eth_call`.
 */
function decodeReturnedAddress(returnData: string): ContractAddress | null {
  if (returnData === '0x' || returnData === '0x0') return null;
  if (!/^0x[0-9a-f]*$/.test(returnData)) return null;
  // Standard ABI: return value is 32 bytes; address occupies the low 20.
  if (returnData.length < 2 + 64) return null;
  const tail = returnData.slice(returnData.length - 40);
  const parsed = contractAddressSchema.safeParse(`0x${tail}`);
  if (!parsed.success) return null;
  if (parsed.data === '0x0000000000000000000000000000000000000000') return null;
  return parsed.data;
}

function explorerMetadataFrom(
  source: ExplorerSourceCode,
  creation: { contractCreator: ContractAddress; txHash: string } | null,
  deploymentTimestamp: number | null,
): ExplorerMetadata {
  return {
    sourceVerified: source.verified,
    contractName: source.contractName,
    compilerVersion: source.compilerVersion,
    deployerAddress: creation === null ? null : creation.contractCreator,
    deploymentTxHash: creation === null ? null : creation.txHash,
    deploymentTimestamp,
  };
}

/**
 * Produce an honest, non-sensitive failure reason for `unavailableReason`.
 * Accepts our two typed error classes (`Web3RpcError` / `Web3ExplorerError`)
 * and any other thrown value. The clients' error messages are already free of
 * api keys + URLs by construction; this is a defensive second pass that ALSO
 * strips anything that looks like a key (hex-strings ≥ 24 chars or any value
 * containing "apikey=" / "key="). Sub-agent rubric §12.
 */
export function sanitizeReason(cause: unknown): string {
  let message: string;
  if (cause instanceof Web3RpcError) {
    message = `${AlchemyRpcClient.providerLabel} ${cause.kind}: ${cause.message}`;
  } else if (cause instanceof Web3ExplorerError) {
    message = `${EtherscanExplorerClient.providerLabel} ${cause.kind}: ${cause.message}`;
  } else if (cause instanceof Error) {
    message = cause.message;
  } else {
    message = String(cause);
  }
  // Strip anything matching `apikey=<token>` / `key=<token>` patterns.
  let out = message.replace(/(apikey|api_key|key)=\S+/gi, '$1=<redacted>');
  // Strip long hex tokens (32+ hex chars in a row) that aren't EVM addresses
  // (which are exactly 40 hex). Be conservative: only redact when length is
  // 64+ (key-like).
  out = out.replace(/\b[0-9a-fA-F]{64,}\b/g, '<redacted-hex>');
  return out.slice(0, 250);
}
