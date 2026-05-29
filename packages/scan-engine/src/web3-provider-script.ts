import type { Web3Chain } from './config';
import { chainIdDecimal, chainIdHex } from './web3-types';

/**
 * Synthetic EIP-1193 provider for the Web3 scan (Sprint A3, T-A3.2).
 *
 * Installed into the page via `page.addInitScript` BEFORE any dApp script
 * runs, so `window.ethereum` exists from the dApp's first import. The provider
 * does three things:
 *
 *  1. **Looks like a wallet.** Sets `isMetaMask = true`, fires
 *     `ethereum#initialized`, sets `selectedAddress`, registers `request`,
 *     `on`, `removeListener` — enough that the standard detection libraries
 *     (`@wagmi/connectors`, `@web3-react`, `RainbowKit`, vanilla
 *     `window.ethereum` checks) all see a wallet and proceed with their flow.
 *     Without this, the dApp never asks for anything → no L1 coverage.
 *
 *  2. **Records every `request({ method, params })` call** into
 *     `window.__ANTHRION_WALLET_REQUESTS__` (a plain array). The harvester
 *     reads this array after navigation (via `page.evaluate`) and the L1
 *     probes (T-A3.3) inspect each record.
 *
 *  3. **Returns plausible fake responses** from a deterministic in-page
 *     table so the dApp's UX flow continues without ever touching a real
 *     wallet or chain. Critically — NO PRIVATE KEY EXISTS ANYWHERE. The
 *     synthetic provider does not "sign" anything: it returns a fixed
 *     65-byte fake signature for every signature request. There is no
 *     EIP-191 / EIP-712 / secp256k1 code path. This is the contract sub-agent
 *     rubric §10 + §11 enforce.
 *
 * Why a window-attached array rather than `page.exposeFunction`:
 *  - Responses are purely deterministic constants; no host-side compute is
 *    needed. A window-attached array is the simpler primitive.
 *  - Avoids Playwright-specific coupling in the injected script, which keeps
 *    the script unit-testable in plain `node:test` against a JSDOM-style
 *    sandbox.
 *  - The harvester Zod-validates the array shape before consuming, so a
 *    hostile in-page script that overwrites the array still cannot inject
 *    malformed records past the trust boundary (CLAUDE.md §3).
 *
 * Synthetic addresses used in responses:
 *  - `eth_requestAccounts` / `eth_accounts` return `SYNTHETIC_ADDRESS`, a
 *    deterministic, recognisably-fake address. Never reuse this constant for
 *    anything that would imply a real wallet (no off-chain UX, no UI hooks).
 */

/** Deterministic fake scanner address. Recognisable as synthetic on first
 * glance (all `0xA1`-bytes), distinct from common test addresses
 * (`0xdead…`, Hardhat default accounts, MetaMask burner addresses). */
export const SYNTHETIC_SCANNER_ADDRESS = '0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1' as const;

/** Deterministic 65-byte fake signature (`r + s + v`, with `v = 0x1c`).
 * Never claims authenticity — it is the same value for every request, so
 * any code that tries to recover an address from it gets the same garbage
 * back. */
export const SYNTHETIC_SIGNATURE =
  '0x' + '00'.repeat(64) + '1c';

/** Deterministic 32-byte fake transaction hash. Recognisable shape: all
 * `0xB2`-bytes. The dApp gets back a hash it can poll the chain for; the
 * scanner never broadcasts the tx, so the hash never resolves on-chain. */
export const SYNTHETIC_TX_HASH = '0x' + 'b2'.repeat(32);

/** Window-level key the synthetic provider records intercepted requests into. */
export const CAPTURE_GLOBAL_KEY = '__ANTHRION_WALLET_REQUESTS__';

/**
 * Build the string the runner passes to `page.addInitScript`. The string is
 * built per-scan because it bakes the configured chain id into the provider's
 * `eth_chainId` / `net_version` responses; constructing once at module load
 * would force the chain at engine-build time, which is wrong.
 *
 * The IIFE pattern (one immediately-invoked function expression) keeps every
 * symbol scoped to the script and avoids polluting `window` with internal
 * helpers. The single global the dApp sees is `window.ethereum`; the single
 * global the harvester reads is `window.__ANTHRION_WALLET_REQUESTS__`.
 *
 * The injected script is pure JavaScript and references NO Node / Playwright
 * APIs — it runs entirely in the page context. The few Node-side constants
 * (synthetic address/signature/tx hash, the chain id) are interpolated as
 * JSON-encoded string literals.
 */
export function buildSyntheticProviderScript(chain: Web3Chain): string {
  const chainIdHexValue = chainIdHex(chain);
  const chainIdDecValue = chainIdDecimal(chain);

  // JSON.stringify is the safe encoder for in-script string literals — never
  // template-concatenate raw values into the script body, even values we
  // control here, because future maintainers should not have to think about
  // escaping rules. Encoding everything keeps the script injection-safe by
  // construction.
  const c = {
    address: JSON.stringify(SYNTHETIC_SCANNER_ADDRESS),
    signature: JSON.stringify(SYNTHETIC_SIGNATURE),
    txHash: JSON.stringify(SYNTHETIC_TX_HASH),
    chainHex: JSON.stringify(chainIdHexValue),
    chainDec: JSON.stringify(chainIdDecValue),
    captureKey: JSON.stringify(CAPTURE_GLOBAL_KEY),
  };

  return `(() => {
  if (typeof window === 'undefined') return;
  if (window.${CAPTURE_GLOBAL_KEY} !== undefined) return; // do not double-install

  const SYNTHETIC_ADDRESS = ${c.address};
  const SYNTHETIC_SIGNATURE = ${c.signature};
  const SYNTHETIC_TX_HASH = ${c.txHash};
  const CHAIN_ID_HEX = ${c.chainHex};
  const CHAIN_ID_DEC = ${c.chainDec};

  const requests = [];
  window[${c.captureKey}] = requests;

  // EIP-1193 error class — wallet libraries unwrap by .code, so the shape matters.
  function rpcError(code, message) {
    const e = new Error(message);
    e.code = code;
    return e;
  }

  let nextSequence = 0;
  function record(method, params, outcome) {
    requests.push({
      sequence: nextSequence++,
      method: String(method),
      params: params === undefined ? null : params,
      timestamp: Date.now(),
      outcome,
    });
  }

  // The single dispatch table the provider serves from. Each entry is a pure
  // function (method, params) → result, OR null to mean "throw 4200 Method not
  // supported". Keeping it data-driven means no per-method if/else sprawl and
  // makes the test surface clear.
  const methods = Object.create(null);

  // ── Connection / identity ─────────────────────────────────────────────────
  methods['eth_requestAccounts'] = () => [SYNTHETIC_ADDRESS];
  methods['eth_accounts'] = () => [SYNTHETIC_ADDRESS];
  methods['eth_chainId'] = () => CHAIN_ID_HEX;
  methods['net_version'] = () => CHAIN_ID_DEC;
  methods['wallet_requestPermissions'] = () => [
    { parentCapability: 'eth_accounts', invoker: null, caveats: [] },
  ];
  methods['wallet_getPermissions'] = () => [
    { parentCapability: 'eth_accounts', invoker: null, caveats: [] },
  ];
  methods['wallet_getCapabilities'] = () => ({});

  // ── State reads (truthful-shape, content arbitrary) ───────────────────────
  methods['eth_getBalance'] = () => '0x0';
  methods['eth_blockNumber'] = () => '0x1';
  methods['eth_getBlockByNumber'] = () => null;
  methods['eth_gasPrice'] = () => '0x3b9aca00'; // 1 gwei
  methods['eth_maxPriorityFeePerGas'] = () => '0x3b9aca00';
  methods['eth_feeHistory'] = () => ({
    oldestBlock: '0x0', baseFeePerGas: ['0x0', '0x0'], gasUsedRatio: [0.5], reward: [['0x0']],
  });
  methods['eth_estimateGas'] = () => '0x5208'; // 21000
  methods['eth_call'] = () => '0x';

  // ── Signature / send (the L1 probe surface, fake responses) ───────────────
  methods['eth_sendTransaction'] = () => SYNTHETIC_TX_HASH;
  methods['wallet_sendCalls'] = () => ({ id: SYNTHETIC_TX_HASH });
  methods['wallet_signCalls'] = () => SYNTHETIC_SIGNATURE;
  methods['eth_signTypedData_v4'] = () => SYNTHETIC_SIGNATURE;
  methods['eth_signTypedData_v3'] = () => SYNTHETIC_SIGNATURE;
  methods['eth_signTypedData_v1'] = () => SYNTHETIC_SIGNATURE;
  methods['eth_signTypedData'] = () => SYNTHETIC_SIGNATURE;
  methods['personal_sign'] = () => SYNTHETIC_SIGNATURE;
  methods['eth_sign'] = () => SYNTHETIC_SIGNATURE;

  // ── Chain / asset management ──────────────────────────────────────────────
  methods['wallet_switchEthereumChain'] = () => null;
  methods['wallet_addEthereumChain'] = () => null;
  methods['wallet_watchAsset'] = () => true;

  // Event listeners are no-ops — we never emit, the dApp's listeners just sit
  // idle. This is fine: dApps do not depend on receiving events to call
  // request().
  const listeners = Object.create(null);
  function on(name, fn) {
    if (typeof name !== 'string' || typeof fn !== 'function') return;
    (listeners[name] = listeners[name] || []).push(fn);
  }
  function removeListener(name, fn) {
    if (typeof name !== 'string') return;
    const list = listeners[name];
    if (!list) return;
    const idx = list.indexOf(fn);
    if (idx >= 0) list.splice(idx, 1);
  }

  async function request(arg) {
    // EIP-1193: request({ method, params }) → Promise<result>.
    if (!arg || typeof arg !== 'object' || typeof arg.method !== 'string') {
      throw rpcError(-32602, 'Invalid request: expected { method, params? }');
    }
    const method = arg.method;
    const params = arg.params;
    const handler = methods[method];
    if (handler === undefined) {
      // EIP-1193 code 4200: Unsupported Method.
      const err = rpcError(4200, 'The method ' + method + ' is not supported by this provider.');
      record(method, params, { kind: 'rejected', errorCode: 4200, errorMessage: err.message });
      throw err;
    }
    let result;
    try {
      result = handler(method, params);
    } catch (cause) {
      const message = cause && cause.message ? String(cause.message) : 'handler threw';
      record(method, params, { kind: 'rejected', errorCode: -32603, errorMessage: message });
      throw rpcError(-32603, message);
    }
    record(method, params, { kind: 'resolved', result });
    return result;
  }

  // The full EIP-1193 provider object. \`enable\` and \`send\` / \`sendAsync\`
  // are the legacy methods modern libraries still occasionally probe for;
  // implementing them as thin wrappers over \`request\` keeps the surface
  // honest without doubling the dispatch.
  const provider = {
    isMetaMask: true,
    isAnthrionScanner: true, // honest tag for any dApp that wants to detect
    chainId: CHAIN_ID_HEX,
    networkVersion: CHAIN_ID_DEC,
    selectedAddress: SYNTHETIC_ADDRESS,
    request,
    on,
    removeListener,
    addListener: on,
    enable() { return request({ method: 'eth_requestAccounts' }); },
    send(methodOrPayload, paramsOrCallback) {
      // Two legacy shapes:
      //   send(method: string, params: unknown[]) → Promise<unknown>
      //   send(payload: { method, params }, cb: (err, res) => void)
      if (typeof methodOrPayload === 'string') {
        return request({ method: methodOrPayload, params: paramsOrCallback });
      }
      const cb = paramsOrCallback;
      request(methodOrPayload).then(
        (result) => cb && cb(null, { id: methodOrPayload.id, jsonrpc: '2.0', result }),
        (err) => cb && cb(err),
      );
      return undefined;
    },
    sendAsync(payload, cb) {
      request(payload).then(
        (result) => cb && cb(null, { id: payload.id, jsonrpc: '2.0', result }),
        (err) => cb && cb(err),
      );
    },
  };

  Object.defineProperty(window, 'ethereum', {
    value: provider,
    writable: true,
    configurable: true,
  });

  // EIP-1193 announcement events. Modern detection libraries (EIP-6963 — the
  // multi-wallet discovery standard) listen for an \`eip6963:announceProvider\`
  // event. We respond to the request event so wagmi/RainbowKit on EIP-6963 see
  // the synthetic provider too.
  function announce6963() {
    const detail = Object.freeze({
      info: Object.freeze({
        uuid: '00000000-0000-4000-a000-anthrion0000',
        name: 'Anthrion Scanner',
        icon: 'data:image/svg+xml;base64,',
        rdns: 'xyz.anthrion.scanner',
      }),
      provider,
    });
    try {
      window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail }));
    } catch (_) {
      // CustomEvent unavailable in some old contexts; safe to ignore.
    }
  }
  try {
    window.addEventListener('eip6963:requestProvider', announce6963);
  } catch (_) { /* no-op */ }
  // Fire once on install so dApps that announce-then-listen also see us.
  announce6963();

  // Legacy ethereum#initialized event some dApps still listen for.
  try {
    window.dispatchEvent(new Event('ethereum#initialized'));
  } catch (_) { /* no-op */ }
})();`;
}
