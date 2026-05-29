import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { Web3Chain } from './config';
import {
  CAPTURE_GLOBAL_KEY,
  SYNTHETIC_SCANNER_ADDRESS,
  SYNTHETIC_SIGNATURE,
  SYNTHETIC_TX_HASH,
  buildSyntheticProviderScript,
} from './web3-provider-script';

/**
 * Unit tests for the synthetic EIP-1193 provider script (T-A3.2 DoD).
 *
 * The script is plain JavaScript that runs in the page realm via
 * `page.addInitScript`. We exercise it directly in Node by treating it as a
 * function body bound to a single named parameter (`window`) — the only free
 * variable the script depends on for its capture + provider install. Free
 * references to `CustomEvent`, `Event`, `Date`, `Object`, `Array`, `Promise`
 * resolve to host globals (Node 18+ ships `CustomEvent`/`Event`).
 *
 * This exercises EVERY method that real dApps actually call (DoD: "Unit tests
 * cover the synthetic provider's EIP-1193 surface"), plus the script's
 * cross-cutting contracts: capture-array shape, EIP-1193 4200 for unknown
 * methods, no double install, legacy `send`/`sendAsync` wrappers, EIP-6963
 * `eip6963:announceProvider` event.
 */

interface SyntheticRequestArg {
  readonly method: string;
  readonly params?: unknown;
  readonly id?: unknown;
}

type SyntheticHandler = (...args: unknown[]) => void;

interface SyntheticProvider {
  isMetaMask: boolean;
  isAnthrionScanner: boolean;
  chainId: string;
  networkVersion: string;
  selectedAddress: string;
  request(arg: SyntheticRequestArg): Promise<unknown>;
  on(name: string, fn: SyntheticHandler): void;
  removeListener(name: string, fn: SyntheticHandler): void;
  addListener(name: string, fn: SyntheticHandler): void;
  enable(): Promise<unknown>;
  send(method: string | SyntheticRequestArg, paramsOrCallback?: unknown): unknown;
  sendAsync(
    payload: SyntheticRequestArg,
    cb: (err: unknown, res: unknown) => void,
  ): void;
}

interface CapturedRequest {
  sequence: number;
  method: string;
  params: unknown;
  timestamp: number;
  outcome:
    | { kind: 'resolved'; result: unknown }
    | { kind: 'rejected'; errorCode: number; errorMessage: string };
}

interface SandboxWindow {
  ethereum?: SyntheticProvider;
  addEventListener(type: string, listener: (event: unknown) => void): void;
  dispatchEvent(event: { type: string; detail?: unknown }): boolean;
  /** Populated by the script at install time. */
  __ANTHRION_WALLET_REQUESTS__?: CapturedRequest[];
}

interface InstallResult {
  window: SandboxWindow;
  provider: SyntheticProvider;
  captured: CapturedRequest[];
  announcedProviders: Array<{ type: string; detail?: unknown }>;
}

function makeWindow(): { window: SandboxWindow; announcedProviders: Array<{ type: string; detail?: unknown }> } {
  const announcedProviders: Array<{ type: string; detail?: unknown }> = [];
  const listeners: Record<string, Array<(event: unknown) => void>> = {};
  const window: SandboxWindow = {
    addEventListener(type, listener) {
      const list = listeners[type] ?? [];
      list.push(listener);
      listeners[type] = list;
    },
    dispatchEvent(event) {
      // Capture announcements for the EIP-6963 assertion.
      announcedProviders.push({ type: event.type, detail: event.detail });
      const list = listeners[event.type] ?? [];
      for (const listener of list) listener(event);
      return true;
    },
  };
  return { window, announcedProviders };
}

function install(chain: Web3Chain = 'ethereum', existing?: SandboxWindow): InstallResult {
  const { window, announcedProviders } = existing === undefined
    ? makeWindow()
    : { window: existing, announcedProviders: [] };
  const script = buildSyntheticProviderScript(chain);
  // The script is an IIFE `(() => { ... })()`. Wrapping it as a Function body
  // with `window` as the only parameter gives the IIFE access to our sandbox
  // window via JS scope, without leaking it to host globals. Other free names
  // (`CustomEvent`, `Event`, `Date`, `Object`, etc.) resolve to the host
  // realm, which is correct — those are the realm intrinsics the script
  // would normally find in a real page.
  const factory = new Function('window', script);
  factory(window);
  const provider = window.ethereum;
  const captured = window[CAPTURE_GLOBAL_KEY];
  if (provider === undefined) {
    throw new Error('synthetic provider failed to install window.ethereum');
  }
  if (captured === undefined) {
    throw new Error('synthetic provider failed to install capture array');
  }
  return { window, provider, captured, announcedProviders };
}

function lastResolved(captured: readonly CapturedRequest[], method: string): CapturedRequest {
  const last = [...captured].reverse().find((c) => c.method === method);
  if (last === undefined) {
    throw new Error(`no captured request for method ${method}`);
  }
  return last;
}

// ── Installation ─────────────────────────────────────────────────────────────

test('install populates window.ethereum with the expected provider surface', () => {
  const { provider } = install('ethereum');
  assert.equal(provider.isMetaMask, true);
  assert.equal(provider.isAnthrionScanner, true);
  assert.equal(provider.chainId, '0x1');
  assert.equal(provider.networkVersion, '1');
  assert.equal(provider.selectedAddress, SYNTHETIC_SCANNER_ADDRESS);
  assert.equal(typeof provider.request, 'function');
  assert.equal(typeof provider.on, 'function');
  assert.equal(typeof provider.removeListener, 'function');
  assert.equal(typeof provider.addListener, 'function');
  assert.equal(typeof provider.enable, 'function');
  assert.equal(typeof provider.send, 'function');
  assert.equal(typeof provider.sendAsync, 'function');
});

test('install bakes the configured chain id into eth_chainId / net_version (base)', async () => {
  const { provider } = install('base');
  assert.equal(provider.chainId, '0x2105');
  assert.equal(provider.networkVersion, '8453');
  assert.equal(await provider.request({ method: 'eth_chainId' }), '0x2105');
  assert.equal(await provider.request({ method: 'net_version' }), '8453');
});

test('a second install on the same window is a no-op (no double install)', () => {
  const { window, provider: first, captured } = install('ethereum');
  assert.equal(captured.length, 0);
  // Trigger a request so the second install would otherwise wipe history.
  void first.request({ method: 'eth_chainId' });
  // Re-running on the same window must not reset the capture array or
  // re-install the provider — the script guards with the capture-array
  // sentinel.
  install('ethereum', window);
  assert.equal(window.ethereum, first, 'window.ethereum must not be re-assigned on second install');
  assert.equal(window[CAPTURE_GLOBAL_KEY], captured, 'capture array must not be re-initialised');
});

// ── EIP-6963 announcement ────────────────────────────────────────────────────

test('install fires an eip6963:announceProvider with the synthetic info', () => {
  const { announcedProviders } = install('ethereum');
  const announces = announcedProviders.filter((e) => e.type === 'eip6963:announceProvider');
  assert.ok(announces.length >= 1, 'expected at least one eip6963:announceProvider dispatch');
  const detail = announces[0]?.detail;
  if (detail === null || typeof detail !== 'object') {
    assert.fail('expected detail to be an object');
  }
  const info = (detail as { info?: { rdns?: string; name?: string } }).info;
  assert.equal(info?.rdns, 'xyz.anthrion.scanner');
  assert.equal(info?.name, 'Anthrion Scanner');
});

test('install fires a legacy ethereum#initialized event', () => {
  const { announcedProviders } = install('ethereum');
  assert.ok(
    announcedProviders.some((e) => e.type === 'ethereum#initialized'),
    'expected ethereum#initialized to be dispatched',
  );
});

// ── Connection / identity methods ────────────────────────────────────────────

test('eth_requestAccounts returns the synthetic address and records the call', async () => {
  const { provider, captured } = install('ethereum');
  const accounts = await provider.request({ method: 'eth_requestAccounts' });
  assert.deepEqual(accounts, [SYNTHETIC_SCANNER_ADDRESS]);
  const last = lastResolved(captured, 'eth_requestAccounts');
  assert.equal(last.sequence, 0);
  assert.equal(last.outcome.kind, 'resolved');
});

test('eth_accounts and wallet_getPermissions return shaped responses', async () => {
  const { provider } = install('ethereum');
  assert.deepEqual(await provider.request({ method: 'eth_accounts' }), [SYNTHETIC_SCANNER_ADDRESS]);
  const perms = await provider.request({ method: 'wallet_getPermissions' });
  assert.ok(Array.isArray(perms) && perms.length === 1, 'expected one permission entry');
});

test('wallet_requestPermissions returns an eth_accounts permission entry', async () => {
  const { provider } = install('ethereum');
  const perms = await provider.request({ method: 'wallet_requestPermissions' });
  if (!Array.isArray(perms) || perms.length !== 1) {
    assert.fail('expected one permission entry');
  }
  const entry = perms[0];
  if (entry === null || typeof entry !== 'object') {
    assert.fail('expected permission entry to be an object');
  }
  assert.equal((entry as { parentCapability?: string }).parentCapability, 'eth_accounts');
});

// ── State reads ──────────────────────────────────────────────────────────────

test('state read methods return truthful-shape but content-arbitrary values', async () => {
  const { provider } = install('ethereum');
  assert.equal(await provider.request({ method: 'eth_getBalance' }), '0x0');
  assert.equal(await provider.request({ method: 'eth_blockNumber' }), '0x1');
  assert.equal(await provider.request({ method: 'eth_gasPrice' }), '0x3b9aca00');
  assert.equal(await provider.request({ method: 'eth_maxPriorityFeePerGas' }), '0x3b9aca00');
  assert.equal(await provider.request({ method: 'eth_estimateGas' }), '0x5208');
  assert.equal(await provider.request({ method: 'eth_call' }), '0x');
});

// ── Signature / send (the L1 probe surface) ──────────────────────────────────

test('eth_sendTransaction returns the synthetic tx hash and records params', async () => {
  const { provider, captured } = install('ethereum');
  const params = [{ from: '0xfromfromfromfromfromfromfromfromfromfrom', to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', data: '0x' }];
  const result = await provider.request({ method: 'eth_sendTransaction', params });
  assert.equal(result, SYNTHETIC_TX_HASH);
  const last = lastResolved(captured, 'eth_sendTransaction');
  assert.deepEqual(last.params, params);
});

test('eth_signTypedData_v4/v3/v1/legacy all return the same synthetic signature', async () => {
  const { provider } = install('ethereum');
  for (const method of [
    'eth_signTypedData_v4',
    'eth_signTypedData_v3',
    'eth_signTypedData_v1',
    'eth_signTypedData',
  ] as const) {
    const sig = await provider.request({ method, params: ['0xabc', { domain: {}, message: {}, types: {}, primaryType: 'X' }] });
    assert.equal(sig, SYNTHETIC_SIGNATURE);
  }
});

test('personal_sign and eth_sign return the synthetic signature', async () => {
  const { provider } = install('ethereum');
  assert.equal(await provider.request({ method: 'personal_sign', params: ['0xdeadbeef', '0xabc'] }), SYNTHETIC_SIGNATURE);
  assert.equal(await provider.request({ method: 'eth_sign', params: ['0xabc', '0xdeadbeef'] }), SYNTHETIC_SIGNATURE);
});

test('wallet_sendCalls returns an envelope with the synthetic batch id', async () => {
  const { provider } = install('ethereum');
  const result = await provider.request({
    method: 'wallet_sendCalls',
    params: [{ version: '1.0', chainId: '0x1', calls: [{ to: '0xabababababababababababababababababababab', data: '0x' }] }],
  });
  if (result === null || typeof result !== 'object') {
    assert.fail('expected envelope object');
  }
  assert.equal((result as { id?: string }).id, SYNTHETIC_TX_HASH);
});

test('wallet_signCalls returns the synthetic signature', async () => {
  const { provider } = install('ethereum');
  const result = await provider.request({ method: 'wallet_signCalls', params: [] });
  assert.equal(result, SYNTHETIC_SIGNATURE);
});

// ── Chain / asset management ─────────────────────────────────────────────────

test('wallet_switchEthereumChain and wallet_addEthereumChain resolve to null', async () => {
  const { provider } = install('ethereum');
  assert.equal(await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x89' }] }), null);
  assert.equal(await provider.request({ method: 'wallet_addEthereumChain', params: [{ chainId: '0x89' }] }), null);
});

test('wallet_watchAsset resolves to true (real wallets return whether the asset was added)', async () => {
  const { provider } = install('ethereum');
  const result = await provider.request({
    method: 'wallet_watchAsset',
    params: { type: 'ERC20', options: { address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', symbol: 'USDC', decimals: 6 } },
  });
  assert.equal(result, true);
});

// ── Unknown methods + capture-record shape ───────────────────────────────────

test('an unknown method rejects with EIP-1193 code 4200 and is recorded as rejected', async () => {
  const { provider, captured } = install('ethereum');
  await assert.rejects(provider.request({ method: 'wallet_madeUpMethod' }), (err: unknown) => {
    if (err === null || typeof err !== 'object') return false;
    const code = (err as { code?: unknown }).code;
    return code === 4200;
  });
  const last = lastResolved(captured, 'wallet_madeUpMethod');
  if (last.outcome.kind !== 'rejected') {
    assert.fail('expected rejected outcome for unknown method');
  }
  assert.equal(last.outcome.errorCode, 4200);
});

test('a request without a method rejects with -32602 invalid-params', async () => {
  const { provider } = install('ethereum');
  await assert.rejects(
    provider.request({ method: '' } as SyntheticRequestArg),
    (err: unknown) => {
      if (err === null || typeof err !== 'object') return false;
      // Empty-string method also falls through to the unsupported-method
      // path (the dispatch table has no entry for ''). Either -32602 (invalid
      // request before dispatch) or 4200 (unsupported method after dispatch)
      // is a faithful EIP-1193 error; both close the safe-by-default surface.
      const code = (err as { code?: unknown }).code;
      return code === -32602 || code === 4200;
    },
  );
});

test('capture records assign monotonic sequence numbers across all requests', async () => {
  const { provider, captured } = install('ethereum');
  await provider.request({ method: 'eth_requestAccounts' });
  await provider.request({ method: 'eth_chainId' });
  await provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' }] });
  assert.equal(captured.length, 3);
  assert.deepEqual(
    captured.map((c) => c.sequence),
    [0, 1, 2],
  );
});

// ── Legacy `enable`, `send`, `sendAsync` ─────────────────────────────────────

test('enable() routes to eth_requestAccounts', async () => {
  const { provider, captured } = install('ethereum');
  const result = await provider.enable();
  assert.deepEqual(result, [SYNTHETIC_SCANNER_ADDRESS]);
  assert.equal(captured.length, 1);
  assert.equal(captured[0]?.method, 'eth_requestAccounts');
});

test('send(method, params) routes through request()', async () => {
  const { provider } = install('ethereum');
  const send = provider.send('eth_chainId', []);
  if (!(send instanceof Promise)) {
    assert.fail('send(method, params) is expected to return a Promise');
  }
  assert.equal(await send, '0x1');
});

test('sendAsync({ method, id }, cb) routes through request() and resolves the callback', async () => {
  const { provider } = install('ethereum');
  await new Promise<void>((resolve, reject) => {
    provider.sendAsync({ method: 'eth_chainId', id: 7 }, (err: unknown, res: unknown) => {
      if (err !== null && err !== undefined) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      if (res === null || typeof res !== 'object') {
        reject(new Error('expected envelope object'));
        return;
      }
      const envelope = res as { id?: unknown; jsonrpc?: unknown; result?: unknown };
      try {
        assert.equal(envelope.id, 7);
        assert.equal(envelope.jsonrpc, '2.0');
        assert.equal(envelope.result, '0x1');
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
        return;
      }
      resolve();
    });
  });
});

// ── Listener registration (no-op event dispatch) ─────────────────────────────

test('on/removeListener track listeners without throwing (no-op event surface)', () => {
  const { provider } = install('ethereum');
  const handler: SyntheticHandler = () => undefined;
  provider.on('accountsChanged', handler);
  provider.removeListener('accountsChanged', handler);
  // Adding the same handler twice and removing once should not throw.
  provider.on('chainChanged', handler);
  provider.on('chainChanged', handler);
  provider.removeListener('chainChanged', handler);
  // No assertions on internal state — the contract is "doesn't throw, doesn't
  // emit anything". The L1 probes never depend on events being emitted.
});
