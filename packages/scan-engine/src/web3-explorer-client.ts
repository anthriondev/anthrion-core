import { z } from 'zod';

import type { Web3Chain } from './config';
import { contractAddressSchema, type ContractAddress } from './web3-types';

/**
 * Etherscan v2 unified explorer client for the Web3 L3 read channel
 * (Sprint A3, T-A3.4).
 *
 * Etherscan v2 unifies the legacy per-chain explorers behind one endpoint
 * (`https://api.etherscan.io/v2/api`) and one API key, with the chain selected
 * via the `chainid` query parameter. The free tier offers 100k calls / day
 * (the founder's chosen tier). Both supported mainnets ride on the same key:
 *   - Ethereum mainnet — chainid=1
 *   - Base mainnet     — chainid=8453
 *
 * Method surface is the minimum the L3 probes (T-A3.5) need:
 *  - `getSourceCode(address)` — verified status, contract name, compiler
 *    version, plus the explorer's own proxy detection + implementation.
 *  - `getContractCreation(address)` — deployer + deployment tx hash. The
 *    deployment timestamp is fetched separately via the RPC client
 *    (`eth_getTransactionByHash` → `eth_getBlockByNumber`), keeping the
 *    explorer call cheap.
 *
 * Secrets handling (sub-agent rubric §12): the api key is held privately and
 * appended only as the `apikey` query parameter when building the request URL.
 * It NEVER appears in error messages, log lines, or any returned value. Error
 * messages use a stable provider label (`Etherscan v2`) and the HTTP / API
 * status, not the URL.
 *
 * Trust boundary (CLAUDE.md §3): every response is Zod-validated before any
 * value is returned. Etherscan's response shape varies meaningfully between
 * "OK" (`status: "1"`) and "error" (`status: "0"`, `result: <string>`); the
 * client treats those as two distinct schemas.
 *
 * Failure mode: throws `Web3ExplorerError` on real failures (network,
 * timeout, non-2xx, malformed response, rate-limit, invalid api key).
 * "Address has no verified source" and "address has no creation record" are
 * NOT failures — they are honest negative answers and surface as the
 * appropriate nullable fields. The provider loader catches the failure cases
 * and degrades to a partial / unavailable `OnChainContext`.
 */

export const ETHERSCAN_V2_API_BASE_URL = 'https://api.etherscan.io/v2/api';

export const DEFAULT_WEB3_EXPLORER_TIMEOUT_MS = 10_000;

/** Etherscan chain ids for the two supported mainnets. */
export function etherscanChainId(chain: Web3Chain): number {
  switch (chain) {
    case 'ethereum':
      return 1;
    case 'base':
      return 8453;
  }
}

/** Result of a `getsourcecode` lookup. All fields nullable; "address is an
 * EOA / unverified contract" surfaces as `verified === false` + nulls, NOT as
 * an error. */
export interface ExplorerSourceCode {
  verified: boolean;
  contractName: string | null;
  compilerVersion: string | null;
  /** True iff the explorer flagged the address as a proxy AND returned an
   * implementation address. The L3 probe still cross-checks via the EIP-1967
   * storage slot — the explorer's proxy flag is a hint, not the source of
   * truth. */
  isProxy: boolean;
  implementation: ContractAddress | null;
}

export interface ExplorerCreationRecord {
  contractCreator: ContractAddress;
  txHash: string;
}

/** Error thrown for genuine failures (NOT for "address not found"). */
export class Web3ExplorerError extends Error {
  readonly kind:
    | 'network'
    | 'timeout'
    | 'http-status'
    | 'malformed-response'
    | 'rate-limited'
    | 'invalid-api-key'
    | 'api-error';
  readonly status: number | undefined;
  constructor(
    kind: Web3ExplorerError['kind'],
    message: string,
    options?: { cause?: unknown; status?: number },
  ) {
    super(message, options);
    this.name = 'Web3ExplorerError';
    this.kind = kind;
    if (options !== undefined) this.status = options.status;
  }
}

const envelopeStringResultSchema = z.object({
  status: z.union([z.literal('0'), z.literal('1')]),
  message: z.string(),
  result: z.string(),
});

const envelopeArrayResultSchema = z.object({
  status: z.union([z.literal('0'), z.literal('1')]),
  message: z.string(),
  result: z.array(z.unknown()),
});

/** Subset of `getsourcecode` result fields the L3 probes consume. */
const sourceCodeEntrySchema = z.object({
  SourceCode: z.string(),
  ContractName: z.string(),
  CompilerVersion: z.string(),
  Proxy: z.string(),
  Implementation: z.string(),
});

const creationEntrySchema = z.object({
  contractCreator: z.string(),
  txHash: z.string(),
});

export interface EtherscanExplorerClientConfig {
  apiKey: string;
  chain: Web3Chain;
  /** Override the Etherscan v2 base URL. Tests set this to a local server. */
  baseUrl?: string;
  /** Per-request timeout (ms). */
  timeoutMs?: number;
}

export class EtherscanExplorerClient {
  static readonly providerLabel = 'Etherscan v2';

  private readonly apiKey: string;
  private readonly chain: Web3Chain;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(config: EtherscanExplorerClientConfig) {
    if (config.apiKey.length === 0) {
      throw new Error(`${EtherscanExplorerClient.providerLabel}: apiKey is required`);
    }
    this.apiKey = config.apiKey;
    this.chain = config.chain;
    this.baseUrl = config.baseUrl ?? ETHERSCAN_V2_API_BASE_URL;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_WEB3_EXPLORER_TIMEOUT_MS;
  }

  /**
   * `module=contract&action=getsourcecode&address=…` (v2 unified).
   *
   * Etherscan returns one result entry per requested address. An unverified
   * contract returns the entry with empty `SourceCode` / `ContractName` /
   * `CompilerVersion` and `Proxy="0"` — that is NOT an error. A genuine
   * failure (rate limit, invalid key, network) throws `Web3ExplorerError`.
   */
  async getSourceCode(address: ContractAddress): Promise<ExplorerSourceCode> {
    const url = this.urlFor({
      module: 'contract',
      action: 'getsourcecode',
      address,
    });
    const raw = await this.fetchJson(url, 'getsourcecode');
    const arr = envelopeArrayResultSchema.safeParse(raw);
    if (!arr.success) {
      // `getsourcecode` may also surface error envelopes as { status: '0', result: <string> }.
      this.maybeThrowFromStringEnvelope(raw, 'getsourcecode');
      throw new Web3ExplorerError(
        'malformed-response',
        `${EtherscanExplorerClient.providerLabel}: getsourcecode response shape was unexpected`,
      );
    }
    if (arr.data.status !== '1') {
      // Etherscan sometimes returns status="0" with an array result for unknown reasons.
      // Surface as an api-error rather than misclassifying as unverified.
      throw new Web3ExplorerError(
        'api-error',
        `${EtherscanExplorerClient.providerLabel}: getsourcecode status=0 (${arr.data.message.slice(0, 200)})`,
      );
    }
    const [first] = arr.data.result;
    const entry = sourceCodeEntrySchema.safeParse(first);
    if (!entry.success) {
      throw new Web3ExplorerError(
        'malformed-response',
        `${EtherscanExplorerClient.providerLabel}: getsourcecode entry shape was unexpected`,
      );
    }
    const verified = entry.data.SourceCode !== '';
    const isProxy = entry.data.Proxy === '1';
    const implementation = isProxy ? safeAddress(entry.data.Implementation) : null;
    return {
      verified,
      contractName: verified && entry.data.ContractName !== '' ? entry.data.ContractName : null,
      compilerVersion:
        verified && entry.data.CompilerVersion !== '' ? entry.data.CompilerVersion : null,
      isProxy: isProxy && implementation !== null,
      implementation,
    };
  }

  /**
   * `module=contract&action=getcontractcreation&contractaddresses=…` (v2).
   *
   * Returns the creation record (deployer + tx hash) when the address is a
   * contract on this chain; returns `null` when the address has no creation
   * record (an EOA, pre-genesis contract, or an explorer that simply doesn't
   * know). A "no data found" response is NOT a failure — it is the explorer's
   * honest negative answer; the provider loader surfaces it as `null` in the
   * resulting `ExplorerMetadata`.
   */
  async getContractCreation(address: ContractAddress): Promise<ExplorerCreationRecord | null> {
    const url = this.urlFor({
      module: 'contract',
      action: 'getcontractcreation',
      contractaddresses: address,
    });
    const raw = await this.fetchJson(url, 'getcontractcreation');
    const arr = envelopeArrayResultSchema.safeParse(raw);
    if (arr.success) {
      if (arr.data.status !== '1') {
        throw new Web3ExplorerError(
          'api-error',
          `${EtherscanExplorerClient.providerLabel}: getcontractcreation status=0 (${arr.data.message.slice(0, 200)})`,
        );
      }
      const [first] = arr.data.result;
      if (first === undefined) return null;
      const entry = creationEntrySchema.safeParse(first);
      if (!entry.success) {
        throw new Web3ExplorerError(
          'malformed-response',
          `${EtherscanExplorerClient.providerLabel}: getcontractcreation entry shape was unexpected`,
        );
      }
      const contractCreator = contractAddressSchema.safeParse(entry.data.contractCreator);
      if (!contractCreator.success) {
        throw new Web3ExplorerError(
          'malformed-response',
          `${EtherscanExplorerClient.providerLabel}: getcontractcreation returned a malformed contractCreator`,
        );
      }
      if (!/^0x[0-9a-fA-F]{64}$/.test(entry.data.txHash)) {
        throw new Web3ExplorerError(
          'malformed-response',
          `${EtherscanExplorerClient.providerLabel}: getcontractcreation returned a malformed txHash`,
        );
      }
      return {
        contractCreator: contractCreator.data,
        txHash: entry.data.txHash.toLowerCase(),
      };
    }
    // No-data shape: { status: '0', message: 'No data found', result: 'No data found' }.
    const str = envelopeStringResultSchema.safeParse(raw);
    if (str.success && str.data.status === '0' && /no data/i.test(str.data.result)) {
      return null;
    }
    this.maybeThrowFromStringEnvelope(raw, 'getcontractcreation');
    throw new Web3ExplorerError(
      'malformed-response',
      `${EtherscanExplorerClient.providerLabel}: getcontractcreation response shape was unexpected`,
    );
  }

  /** Build a v2-unified URL. The api key + chainid are appended here so the
   * caller cannot forget either. The full URL (including the api key) is NEVER
   * embedded in error messages. */
  private urlFor(params: Record<string, string>): string {
    const url = new URL(this.baseUrl);
    url.searchParams.set('chainid', String(etherscanChainId(this.chain)));
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    url.searchParams.set('apikey', this.apiKey);
    return url.toString();
  }

  /** Fetch + parse + classify HTTP-status / rate-limit / network failures
   * UNIFORMLY for every action. */
  private async fetchJson(url: string, action: string): Promise<unknown> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(url, { method: 'GET', signal: controller.signal });
    } catch (cause) {
      if (timedOut) {
        throw new Web3ExplorerError(
          'timeout',
          `${EtherscanExplorerClient.providerLabel}: ${action} timed out after ${this.timeoutMs}ms`,
          { cause },
        );
      }
      throw new Web3ExplorerError(
        'network',
        `${EtherscanExplorerClient.providerLabel}: ${action} network failure`,
        { cause },
      );
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 429) {
      throw new Web3ExplorerError(
        'rate-limited',
        `${EtherscanExplorerClient.providerLabel}: ${action} rate-limited (HTTP 429)`,
        { status: 429 },
      );
    }
    if (!response.ok) {
      throw new Web3ExplorerError(
        'http-status',
        `${EtherscanExplorerClient.providerLabel}: ${action} HTTP ${response.status}`,
        { status: response.status },
      );
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch (cause) {
      throw new Web3ExplorerError(
        'malformed-response',
        `${EtherscanExplorerClient.providerLabel}: ${action} response was not JSON`,
        { cause },
      );
    }
    return json;
  }

  /** When the raw response decodes to the string-result envelope (`{ status:
   * '0', result: '<msg>' }`), inspect the message for known soft errors
   * (rate limit / invalid key) and throw the matching `Web3ExplorerError`. */
  private maybeThrowFromStringEnvelope(raw: unknown, action: string): void {
    const str = envelopeStringResultSchema.safeParse(raw);
    if (!str.success) return;
    if (str.data.status === '0') {
      const lower = str.data.result.toLowerCase();
      if (lower.includes('rate limit')) {
        throw new Web3ExplorerError(
          'rate-limited',
          `${EtherscanExplorerClient.providerLabel}: ${action} reported a rate-limit`,
        );
      }
      if (lower.includes('invalid api key')) {
        throw new Web3ExplorerError(
          'invalid-api-key',
          `${EtherscanExplorerClient.providerLabel}: ${action} reported an invalid API key`,
        );
      }
      throw new Web3ExplorerError(
        'api-error',
        `${EtherscanExplorerClient.providerLabel}: ${action} api error (${str.data.result.slice(0, 200)})`,
      );
    }
  }
}

function safeAddress(value: string): ContractAddress | null {
  const parsed = contractAddressSchema.safeParse(value);
  if (!parsed.success) return null;
  if (parsed.data === '0x0000000000000000000000000000000000000000') return null;
  return parsed.data;
}
