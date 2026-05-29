import { z } from 'zod';

import type { Web3Chain } from './config';
import { contractAddressSchema, type ContractAddress } from './web3-types';

/**
 * Alchemy JSON-RPC client for the Web3 L3 read channel (Sprint A3, T-A3.4).
 *
 * Chain support follows the founder's RPC decision: Alchemy free tier (30M
 * compute units / month, archive included). Two endpoints — one per supported
 * mainnet (TECH_STACK.md: Ethereum + Base). The client takes `apiKey` + `chain`
 * and builds the URL itself; the caller (sandbox-runtime, T-A3.7) reads
 * `ALCHEMY_API_KEY` from the env at the boundary, parses with Zod, and injects
 * the value here — `scan-engine` stays pure (no `process.env`).
 *
 * Method surface is strictly READ-ONLY (sub-agent rubric §11): only the three
 * RPC methods L3 actually needs — `eth_getCode`, `eth_getStorageAt`, `eth_call`
 * — plus `eth_getTransactionByHash` and `eth_getBlockByNumber` for deployment
 * timestamp lookup. There is NO method for `eth_sendRawTransaction`, signing,
 * or any state mutation: the class deliberately does not expose a generic
 * `request(method, params)` so an L3 probe cannot smuggle a write call.
 *
 * Secrets handling (sub-agent rubric §12): `apiKey` is held privately, used
 * only to construct the request URL, and NEVER appears in:
 *  - thrown error messages (only the labelled provider name + status appears)
 *  - log lines
 *  - any returned data
 *
 * Trust boundary (CLAUDE.md §3): every JSON-RPC response is Zod-validated
 * before any value is returned. Malformed responses raise `Web3RpcError`
 * with a generic message — they never leak through as `unknown` to a caller.
 *
 * Failure mode: the client throws `Web3RpcError` on network failure, timeout,
 * non-2xx response, malformed JSON, or a JSON-RPC `error` field. The
 * `RemoteOnChainContextProvider` (web3-onchain-context-loader.ts) catches
 * these per sub-channel and degrades to a partial / unavailable
 * `OnChainContext` — a provider hiccup never crashes a Web3 scan.
 */

/** Public Alchemy mainnet URLs, by chain. The API key is appended as the last
 * path segment (Alchemy's documented URL shape:
 * `https://<chain>-mainnet.g.alchemy.com/v2/<API_KEY>`). */
export const ALCHEMY_RPC_BASE_URL_ETHEREUM = 'https://eth-mainnet.g.alchemy.com/v2';
export const ALCHEMY_RPC_BASE_URL_BASE = 'https://base-mainnet.g.alchemy.com/v2';

/** Default per-request timeout (ms). Read-only RPC calls are fast; a hung
 * provider is what this guards. The L3 runner ALSO catches provider failures
 * into a coverage gap, so this timeout is a real cap — not a budget shaving. */
export const DEFAULT_WEB3_RPC_TIMEOUT_MS = 10_000;

/** Standard EVM 32-byte slot value returned by `eth_getStorageAt` when the
 * slot has never been written (`bytes32(0)`). Strings here are kept LOWER-CASE
 * so callers can string-equality compare without re-normalising. */
export const ZERO_STORAGE_SLOT = '0x' + '00'.repeat(32);

/**
 * EIP-1967 storage slot for the implementation address of a transparent /
 * UUPS proxy: `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)`.
 * Reading this slot is the canonical way to inspect an OpenZeppelin proxy's
 * implementation without trusting the proxy's own `implementation()` accessor
 * (which a malicious proxy could lie about).
 */
export const EIP1967_IMPLEMENTATION_SLOT =
  '0x360894a13ba1a3210667c828492db98dcbf16f43eebb83b04c50ef0b34da91ee';

/** EIP-1967 admin slot:
 * `bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)`. The admin is the
 * address authorised to upgrade the proxy; an EOA value here is the
 * `eoa-admin-single-key` indicator the L3 probe surfaces. */
export const EIP1967_ADMIN_SLOT =
  '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';

/** EIP-1967 beacon slot:
 * `bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)`. Read separately
 * from the implementation slot so L3 can tell beacon-style proxies (where the
 * beacon contract returns the implementation) apart from transparent ones. */
export const EIP1967_BEACON_SLOT =
  '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';

/** ERC-173 `owner()` 4-byte selector — used by `eth_call` to read the
 * contract's `owner` accessor without a deployed ABI. */
export const SELECTOR_OWNER = '0x8da5cb5b';

/** Ownable2Step `pendingOwner()` selector. Many modern contracts use this two-
 * step ownership transfer; reading it cheaply lets L3 surface "ownership in
 * flight" too. */
export const SELECTOR_PENDING_OWNER = '0xe30c3978';

/** Error thrown by every RPC method. Carries an honest, non-sensitive message
 * — the provider name + the status code / failure kind. The Alchemy API key is
 * NEVER part of the message (sub-agent rubric §12). */
export class Web3RpcError extends Error {
  readonly kind: 'network' | 'timeout' | 'http-status' | 'malformed-response' | 'rpc-error';
  readonly status: number | undefined;
  constructor(
    kind: Web3RpcError['kind'],
    message: string,
    options?: { cause?: unknown; status?: number },
  ) {
    super(message, options);
    this.name = 'Web3RpcError';
    this.kind = kind;
    if (options !== undefined) this.status = options.status;
  }
}

const jsonRpcResultSchema = z.object({
  jsonrpc: z.literal('2.0').optional(),
  id: z.union([z.number(), z.string(), z.null()]).optional(),
  result: z.unknown(),
});

const jsonRpcErrorSchema = z.object({
  jsonrpc: z.literal('2.0').optional(),
  id: z.union([z.number(), z.string(), z.null()]).optional(),
  error: z.object({
    code: z.number().int().optional(),
    message: z.string(),
    data: z.unknown().optional(),
  }),
});

/** A single `eth_getTransactionByHash` response we care about. */
const transactionResponseSchema = z
  .object({
    blockNumber: z.string().regex(/^0x[0-9a-fA-F]+$/).nullable(),
    blockHash: z.string().optional(),
    from: z.string().optional(),
    to: z.string().nullable().optional(),
  })
  .nullable();

/** A subset of `eth_getBlockByNumber` we care about — only the timestamp. */
const blockHeaderResponseSchema = z
  .object({
    timestamp: z.string().regex(/^0x[0-9a-fA-F]+$/),
  })
  .nullable();

export interface AlchemyRpcClientConfig {
  /** Alchemy API key. NEVER logged or exposed in error messages (rubric §12). */
  apiKey: string;
  /** Chain selects the per-chain Alchemy URL when `baseUrl` is not overridden. */
  chain: Web3Chain;
  /** Override the Alchemy base URL (the `v2`-suffixed prefix; the api key is
   * appended as the final path segment). Tests set this to a local server URL;
   * production uses the chain-derived default. */
  baseUrl?: string;
  /** Per-request timeout (ms). Default `DEFAULT_WEB3_RPC_TIMEOUT_MS`. */
  timeoutMs?: number;
}

/**
 * Alchemy read-only JSON-RPC client. Public method surface is fixed and
 * read-only — no generic `request(method, params)` is exposed, so an L3 probe
 * cannot smuggle a state-mutating call.
 */
export class AlchemyRpcClient {
  /** Stable provider label used in error messages, NEVER includes the API key. */
  static readonly providerLabel = 'Alchemy RPC';

  private readonly url: string;
  private readonly timeoutMs: number;
  private nextId = 1;

  constructor(config: AlchemyRpcClientConfig) {
    if (config.apiKey.length === 0) {
      throw new Error(`${AlchemyRpcClient.providerLabel}: apiKey is required`);
    }
    const base =
      config.baseUrl ??
      (config.chain === 'ethereum' ? ALCHEMY_RPC_BASE_URL_ETHEREUM : ALCHEMY_RPC_BASE_URL_BASE);
    // Append the api key as the last path segment per Alchemy's documented URL shape.
    this.url = base.endsWith('/') ? `${base}${config.apiKey}` : `${base}/${config.apiKey}`;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_WEB3_RPC_TIMEOUT_MS;
  }

  /**
   * `eth_getCode(address, 'latest')` → bytecode hex string (`0x` for an EOA).
   * Wrap result in `contractAddressSchema`? No — the result is bytecode, not
   * an address. We just validate that it is a 0x-prefixed hex string.
   */
  async getCode(address: ContractAddress): Promise<string> {
    const raw = await this.callRpc('eth_getCode', [address, 'latest']);
    return parseHexBytes(raw, `${AlchemyRpcClient.providerLabel}: eth_getCode`);
  }

  /**
   * `eth_getStorageAt(address, slot, 'latest')` → 32-byte hex string. Returns
   * the canonical `ZERO_STORAGE_SLOT` (`0x00…00`) when the slot is unwritten.
   * Storage values are always 32 bytes; we normalise to lower-case
   * `0x`-prefixed 64-hex form so callers can string-equality compare.
   */
  async getStorageAt(address: ContractAddress, slot: string): Promise<string> {
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(slot)) {
      throw new Error(`${AlchemyRpcClient.providerLabel}: invalid slot ${slot}`);
    }
    const raw = await this.callRpc('eth_getStorageAt', [address, slot, 'latest']);
    if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]{0,64}$/.test(raw)) {
      throw new Web3RpcError(
        'malformed-response',
        `${AlchemyRpcClient.providerLabel}: eth_getStorageAt returned a malformed value`,
      );
    }
    // Normalise: lower-case, left-pad to 64 hex chars (the slot is always 32 bytes
    // even when the chain returns it short).
    const lower = raw.toLowerCase();
    const body = lower.slice(2);
    if (body.length === 64) return lower;
    return `0x${body.padStart(64, '0')}`;
  }

  /**
   * `eth_call({ to: address, data }, 'latest')` → return-data hex. Use for
   * standard read accessors (`owner()`, `pendingOwner()`, role mappings).
   * Returns `'0x'` when the function does not exist or reverts — callers
   * treat that as "not exposed", not as a hard failure (per the L3 spec).
   */
  async call(address: ContractAddress, data: string): Promise<string> {
    if (!/^0x[0-9a-fA-F]*$/.test(data)) {
      throw new Error(`${AlchemyRpcClient.providerLabel}: invalid calldata ${data}`);
    }
    try {
      const raw = await this.callRpc('eth_call', [{ to: address, data }, 'latest']);
      return parseHexBytes(raw, `${AlchemyRpcClient.providerLabel}: eth_call`);
    } catch (cause) {
      if (cause instanceof Web3RpcError && cause.kind === 'rpc-error') {
        // A revert is an honest "not exposed" signal — many contracts simply
        // don't implement `owner()`. Surface as empty return data; the caller
        // (RemoteOnChainContextProvider) then classifies ownerKind='not-exposed'.
        return '0x';
      }
      throw cause;
    }
  }

  /** `eth_getTransactionByHash(hash)` → transaction with `blockNumber`. */
  async getTransactionBlockNumber(hash: string): Promise<string | null> {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
      throw new Error(`${AlchemyRpcClient.providerLabel}: invalid tx hash`);
    }
    const raw = await this.callRpc('eth_getTransactionByHash', [hash]);
    const parsed = transactionResponseSchema.safeParse(raw);
    if (!parsed.success) {
      throw new Web3RpcError(
        'malformed-response',
        `${AlchemyRpcClient.providerLabel}: eth_getTransactionByHash returned a malformed result`,
      );
    }
    if (parsed.data === null) return null;
    return parsed.data.blockNumber;
  }

  /** `eth_getBlockByNumber(number, false)` → block timestamp (unix seconds). */
  async getBlockTimestamp(blockNumber: string): Promise<number | null> {
    if (!/^0x[0-9a-fA-F]+$/.test(blockNumber)) {
      throw new Error(`${AlchemyRpcClient.providerLabel}: invalid block number`);
    }
    const raw = await this.callRpc('eth_getBlockByNumber', [blockNumber, false]);
    const parsed = blockHeaderResponseSchema.safeParse(raw);
    if (!parsed.success) {
      throw new Web3RpcError(
        'malformed-response',
        `${AlchemyRpcClient.providerLabel}: eth_getBlockByNumber returned a malformed result`,
      );
    }
    if (parsed.data === null) return null;
    const seconds = Number.parseInt(parsed.data.timestamp.slice(2), 16);
    if (!Number.isFinite(seconds) || seconds < 0) return null;
    return seconds;
  }

  /** Internal: POST a single JSON-RPC envelope and return its `result`. */
  private async callRpc(method: string, params: readonly unknown[]): Promise<unknown> {
    const id = this.nextId++;
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params });

    let response: Response;
    try {
      response = await this.post(body);
    } catch (cause) {
      // post() throws Web3RpcError directly for network/timeout
      if (cause instanceof Web3RpcError) throw cause;
      throw new Web3RpcError('network', `${AlchemyRpcClient.providerLabel}: network failure`, {
        cause,
      });
    }

    if (!response.ok) {
      throw new Web3RpcError(
        'http-status',
        `${AlchemyRpcClient.providerLabel}: HTTP ${response.status}`,
        { status: response.status },
      );
    }

    let json: unknown;
    try {
      json = await response.json();
    } catch (cause) {
      throw new Web3RpcError(
        'malformed-response',
        `${AlchemyRpcClient.providerLabel}: response was not JSON`,
        { cause },
      );
    }

    const errEnvelope = jsonRpcErrorSchema.safeParse(json);
    if (errEnvelope.success) {
      throw new Web3RpcError(
        'rpc-error',
        `${AlchemyRpcClient.providerLabel}: ${method}: ${errEnvelope.data.error.message.slice(0, 200)}`,
      );
    }
    const okEnvelope = jsonRpcResultSchema.safeParse(json);
    if (!okEnvelope.success) {
      throw new Web3RpcError(
        'malformed-response',
        `${AlchemyRpcClient.providerLabel}: ${method} response did not match JSON-RPC envelope`,
      );
    }
    return okEnvelope.data.result;
  }

  private async post(body: string): Promise<Response> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);
    try {
      return await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        signal: controller.signal,
      });
    } catch (cause) {
      if (timedOut) {
        throw new Web3RpcError(
          'timeout',
          `${AlchemyRpcClient.providerLabel}: request timed out after ${this.timeoutMs}ms`,
          { cause },
        );
      }
      throw new Web3RpcError('network', `${AlchemyRpcClient.providerLabel}: network failure`, {
        cause,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Decode the low 20 bytes of a 32-byte hex slot value as an EVM address.
 * Returns the address (lower-cased) or `null` when the slot is the zero slot.
 * Used by both the proxy probe (implementation / admin slot read) and the
 * admin probe (owner() return parsed as an address).
 */
export function decodeAddressFromStorage(slotValue: string): ContractAddress | null {
  const normalised = slotValue.toLowerCase();
  if (normalised === ZERO_STORAGE_SLOT) return null;
  if (!/^0x[0-9a-f]{64}$/.test(normalised)) return null;
  const candidate = `0x${normalised.slice(2 + 24)}`;
  const parsed = contractAddressSchema.safeParse(candidate);
  if (!parsed.success) return null;
  // Zero-padded slot (any address bits zero) is the null-address sentinel.
  if (parsed.data === '0x0000000000000000000000000000000000000000') return null;
  return parsed.data;
}

/** Internal helper: ensure the JSON-RPC `result` is a `0x`-prefixed hex string. */
function parseHexBytes(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]*$/.test(value)) {
    throw new Web3RpcError('malformed-response', `${label}: expected 0x-hex result`);
  }
  return value.toLowerCase();
}
