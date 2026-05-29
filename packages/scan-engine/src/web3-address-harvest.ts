import {
  contractAddressSchema,
  type ContractAddress,
  type ReferencedContract,
  type WalletRequest,
} from './web3-types';

/**
 * Address harvester for the Web3 scan (Sprint A3, T-A3.2).
 *
 * Two sources, with provenance preserved on every `ReferencedContract`:
 *
 *  1. **Intercepted wallet requests.** For each `WalletRequest`, pick out the
 *     parameter slot(s) that real dApps place contract addresses in: the `to`
 *     field of `eth_sendTransaction` / `eth_call`, the `verifyingContract` of
 *     EIP-712 typed-data domains, the contract address of
 *     `wallet_watchAsset`, the implementation / spender / `to` slots inside
 *     `eth_sendTransaction` calldata when the dApp surfaces it as a typed
 *     object (some libraries do — most don't, but we extract what we can).
 *
 *  2. **DOM-rendered HTML.** Many dApp UIs name contract addresses outside the
 *     wallet flow (button data attrs, explorer hrefs, deep-linkable URL path
 *     segments). A simple `0x[a-fA-F0-9]{40}` scan over the rendered HTML
 *     surfaces these. Weaker signal than a wallet request, so the harvester
 *     marks the origin honestly and the L3 probes can downweight if needed.
 *
 * Output is de-duplicated by lower-cased address — the SAME address visible
 * from both sources is reported ONCE, attributed to the strongest provenance
 * available (wallet request beats DOM reference).
 *
 * Trust boundary: every candidate string is run through `contractAddressSchema`
 * (regex + lower-case transform) before it becomes a `ContractAddress`. Garbage
 * input from a hostile DOM / hostile-shaped wallet params is filtered, not
 * trusted (CLAUDE.md §3).
 */

/** Regex for EVM addresses inside arbitrary text (no anchors, case-insensitive).
 * Word-boundary on both sides keeps "0xdeadbeef…cafefacedeadbeef0123" from
 * splitting into a false 40-hex-char match in the middle of a longer hex blob
 * (e.g. a calldata field rendered inline). */
const EVM_ADDRESS_TEXT_REGEX = /\b0x[0-9a-fA-F]{40}\b/g;

/** The "all zeros" EVM address means "no contract" in every standard context
 * (e.g. ERC-721 mint event `from`). Drop it from harvested results so we never
 * recommend looking it up in L3. */
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** Try to parse a raw string as an EVM address. Returns the canonical
 * lower-cased form, or undefined if it does not match the schema. */
function tryParseAddress(value: unknown): ContractAddress | undefined {
  if (typeof value !== 'string') return undefined;
  const parsed = contractAddressSchema.safeParse(value);
  if (!parsed.success) return undefined;
  if (parsed.data === ZERO_ADDRESS) return undefined;
  return parsed.data;
}

interface AddressSighting {
  address: ContractAddress;
  origin: ReferencedContract['origin'];
  walletRequestSequence?: number;
  walletRequestMethod?: string;
}

/**
 * Walk a wallet request's `params` and yield every contract address found at
 * the slots where modern dApps actually place them. The walk is shallow on
 * purpose — we look at named fields, not at arbitrary byte blobs. Calldata
 * decoding (e.g. unwrapping a `0xa9059cbb…` ERC-20 transfer to extract the
 * recipient) is out of scope for T-A3.2; that level of analysis belongs to
 * the L1 probes (T-A3.3) when they need it.
 */
function* sightingsFromWalletRequest(req: WalletRequest): Generator<AddressSighting> {
  const { params, method, sequence } = req;

  function emit(address: ContractAddress): AddressSighting {
    return {
      address,
      origin: 'wallet-request',
      walletRequestSequence: sequence,
      walletRequestMethod: method,
    };
  }

  // Helper: read a field from a plain-object slot. Returns undefined if the
  // input is not a plain object or the field is missing/non-string.
  function readField(obj: unknown, field: string): string | undefined {
    if (obj === null || typeof obj !== 'object') return undefined;
    const value = (obj as Record<string, unknown>)[field];
    return typeof value === 'string' ? value : undefined;
  }

  // eth_sendTransaction / eth_call: params[0].to is the target contract.
  if (
    method === 'eth_sendTransaction' ||
    method === 'eth_call' ||
    method === 'eth_estimateGas'
  ) {
    const txObject = Array.isArray(params) ? params[0] : params;
    const to = readField(txObject, 'to');
    const addr = tryParseAddress(to);
    if (addr !== undefined) yield emit(addr);
    return;
  }

  // EIP-712 typed-data signatures: the `domain.verifyingContract` slot. Modern
  // dApps pass params as `[address, typedData]` — typedData may be the parsed
  // object or a JSON string (legacy callers).
  if (
    method === 'eth_signTypedData_v4' ||
    method === 'eth_signTypedData_v3' ||
    method === 'eth_signTypedData_v1' ||
    method === 'eth_signTypedData'
  ) {
    const typedData = Array.isArray(params) ? params[1] : undefined;
    let parsed: unknown = typedData;
    if (typeof typedData === 'string') {
      try {
        parsed = JSON.parse(typedData);
      } catch {
        parsed = undefined;
      }
    }
    const domain =
      parsed !== null && typeof parsed === 'object'
        ? (parsed as Record<string, unknown>)['domain']
        : undefined;
    const verifyingContract = readField(domain, 'verifyingContract');
    const addr = tryParseAddress(verifyingContract);
    if (addr !== undefined) yield emit(addr);
    return;
  }

  // wallet_watchAsset: params.options.address is the token contract.
  if (method === 'wallet_watchAsset') {
    const options =
      params !== null && typeof params === 'object'
        ? (params as Record<string, unknown>)['options']
        : undefined;
    const address = readField(options, 'address');
    const addr = tryParseAddress(address);
    if (addr !== undefined) yield emit(addr);
    return;
  }

  // wallet_sendCalls (EIP-5792): params[0].calls[].to is each batched target.
  if (method === 'wallet_sendCalls') {
    const batch = Array.isArray(params) ? params[0] : params;
    const calls =
      batch !== null && typeof batch === 'object'
        ? (batch as Record<string, unknown>)['calls']
        : undefined;
    if (Array.isArray(calls)) {
      for (const call of calls) {
        const to = readField(call, 'to');
        const addr = tryParseAddress(to);
        if (addr !== undefined) yield emit(addr);
      }
    }
    return;
  }

  // Other methods: no canonical address slot. Falls through.
}

/**
 * De-duplicate a list of sightings by lower-cased address, preferring
 * `wallet-request` provenance over `dom-reference` when the same address
 * comes from both sources. Stable order: first sighting wins for ties.
 */
function dedupeByAddress(sightings: readonly AddressSighting[]): ReferencedContract[] {
  const byAddress = new Map<ContractAddress, AddressSighting>();
  for (const sighting of sightings) {
    const existing = byAddress.get(sighting.address);
    if (existing === undefined) {
      byAddress.set(sighting.address, sighting);
      continue;
    }
    // Upgrade DOM reference to wallet-request reference if the latter comes in.
    if (existing.origin === 'dom-reference' && sighting.origin === 'wallet-request') {
      byAddress.set(sighting.address, sighting);
    }
  }
  return Array.from(byAddress.values()).map((sighting) => {
    const out: ReferencedContract = {
      address: sighting.address,
      origin: sighting.origin,
    };
    if (sighting.walletRequestSequence !== undefined) {
      out.walletRequestSequence = sighting.walletRequestSequence;
    }
    if (sighting.walletRequestMethod !== undefined) {
      out.walletRequestMethod = sighting.walletRequestMethod;
    }
    return out;
  });
}

/**
 * Public entry point. Extract referenced contract addresses from the L1
 * harvest (intercepted wallet requests) and the rendered HTML (DOM).
 */
export function harvestReferencedContracts(input: {
  walletRequests: readonly WalletRequest[];
  html: string;
}): ReferencedContract[] {
  const sightings: AddressSighting[] = [];
  for (const req of input.walletRequests) {
    for (const sighting of sightingsFromWalletRequest(req)) {
      sightings.push(sighting);
    }
  }
  // DOM pass — append after wallet-request sightings so dedupe naturally
  // keeps the stronger provenance when the same address appears in both.
  const matches = input.html.match(EVM_ADDRESS_TEXT_REGEX);
  if (matches !== null) {
    for (const raw of matches) {
      const addr = tryParseAddress(raw);
      if (addr !== undefined) {
        sightings.push({ address: addr, origin: 'dom-reference' });
      }
    }
  }
  return dedupeByAddress(sightings);
}
