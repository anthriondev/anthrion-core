import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import {
  AlchemyRpcClient,
  EIP1967_ADMIN_SLOT,
  EIP1967_IMPLEMENTATION_SLOT,
  SELECTOR_OWNER,
  SELECTOR_PENDING_OWNER,
  ZERO_STORAGE_SLOT,
} from './web3-rpc-client';
import { EtherscanExplorerClient } from './web3-explorer-client';
import {
  RemoteOnChainContextProvider,
  sanitizeReason,
} from './web3-onchain-context-loader';
import type { ContractAddress } from './web3-types';

/**
 * Integration tests for `RemoteOnChainContextProvider` (T-A3.4).
 *
 * Two ephemeral HTTP servers (mock Alchemy + mock Etherscan v2) wired to the
 * real client classes — proving the WHOLE loader end-to-end including JSON-RPC
 * envelope handling, Etherscan v2 envelope handling, graceful degradation,
 * caching, and rubric §12 (api keys never appear in the resulting
 * `unavailableReason`).
 */

const ALCHEMY_KEY = 'test-alchemy-secret';
const ETHERSCAN_KEY = 'test-etherscan-secret';

const CONTRACT_ADDR = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as ContractAddress;
const EOA_ADDR = '0xdeadbeef00000000000000000000000000000001' as ContractAddress;
const IMPLEMENTATION = '0xc0de0c0de0c0de0c0de0c0de0c0de0c0de0c0de0' as ContractAddress;
const ADMIN_EOA = '0xfeed00feed00feed00feed00feed00feed00feed' as ContractAddress;
const OWNER_EOA = '0xfacefacefacefacefacefacefacefacefaceface' as ContractAddress;
const DEPLOYER = '0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef' as ContractAddress;
const DEPLOY_TX = `0x${'aa'.repeat(32)}`;
const DEPLOY_BLOCK = '0x1234';
const DEPLOY_TIMESTAMP_HEX = '0x65000000'; // 2023-09-12 ~ unix 1694469120

interface MockServer {
  url: string;
  /** Hits per JSON-RPC method (Alchemy) or per `action` query param (Etherscan). */
  hits: Record<string, number>;
  close: () => Promise<void>;
}

function recordHit(hits: Record<string, number>, key: string): void {
  hits[key] = (hits[key] ?? 0) + 1;
}

async function startAlchemyMock(
  responder: (method: string, params: unknown[]) => unknown | { error: { code: number; message: string } } | 'http-500' | 'hang',
): Promise<MockServer> {
  const hits: Record<string, number> = {};
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
      const env = body as { id: number; method: string; params: unknown[] };
      recordHit(hits, env.method);
      const result = responder(env.method, env.params);
      if (result === 'hang') return; // never respond
      if (result === 'http-500') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end('{}');
        return;
      }
      if (typeof result === 'object' && result !== null && 'error' in result) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({ jsonrpc: '2.0', id: env.id, error: (result as { error: { code: number; message: string } }).error }),
        );
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: env.id, result }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('alchemy mock failed to bind');
  }
  return {
    url: `http://127.0.0.1:${address.port}`,
    hits,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function startEtherscanMock(
  responder: (action: string, params: URLSearchParams) => unknown | 'http-500' | 'http-429',
): Promise<MockServer> {
  const hits: Record<string, number> = {};
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://placeholder');
    const action = url.searchParams.get('action') ?? '';
    recordHit(hits, action);
    const result = responder(action, url.searchParams);
    if (result === 'http-500') {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end('{}');
      return;
    }
    if (result === 'http-429') {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end('{}');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('etherscan mock failed to bind');
  }
  return {
    url: `http://127.0.0.1:${address.port}/v2/api`,
    hits,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

// ─── Happy path: a contract with proxy + owner + verified source ────────────

test('full happy path: verified proxy with EOA admin + EOA owner → availability=complete', async () => {
  const alchemy = await startAlchemyMock((method, params) => {
    if (method === 'eth_getCode') {
      const addr = (params[0] as string).toLowerCase();
      if (addr === CONTRACT_ADDR) return '0x6080'; // contract bytecode
      if (addr === OWNER_EOA) return '0x'; // owner is EOA
      return '0x';
    }
    if (method === 'eth_getStorageAt') {
      const slot = (params[1] as string).toLowerCase();
      if (slot === EIP1967_IMPLEMENTATION_SLOT) {
        return `0x000000000000000000000000${IMPLEMENTATION.slice(2)}`;
      }
      if (slot === EIP1967_ADMIN_SLOT) {
        return `0x000000000000000000000000${ADMIN_EOA.slice(2)}`;
      }
      return ZERO_STORAGE_SLOT;
    }
    if (method === 'eth_call') {
      const call = params[0] as { data: string };
      if (call.data === SELECTOR_OWNER) {
        return `0x000000000000000000000000${OWNER_EOA.slice(2)}`;
      }
      if (call.data === SELECTOR_PENDING_OWNER) {
        return '0x';
      }
      return '0x';
    }
    if (method === 'eth_getTransactionByHash') {
      return { blockNumber: DEPLOY_BLOCK };
    }
    if (method === 'eth_getBlockByNumber') {
      return { timestamp: DEPLOY_TIMESTAMP_HEX, number: DEPLOY_BLOCK };
    }
    return null;
  });
  const etherscan = await startEtherscanMock((action) => {
    if (action === 'getsourcecode') {
      return {
        status: '1',
        message: 'OK',
        result: [
          {
            SourceCode: 'contract C {}',
            ABI: '[]',
            ContractName: 'TransparentUpgradeableProxy',
            CompilerVersion: 'v0.8.20+commit',
            Proxy: '1',
            Implementation: IMPLEMENTATION,
          },
        ],
      };
    }
    if (action === 'getcontractcreation') {
      return {
        status: '1',
        message: 'OK',
        result: [{ contractAddress: CONTRACT_ADDR, contractCreator: DEPLOYER, txHash: DEPLOY_TX }],
      };
    }
    return null;
  });
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });
    const ctx = await loader.getContractContext(CONTRACT_ADDR);

    assert.equal(ctx.kind, 'contract');
    assert.equal(ctx.availability, 'complete');
    assert.equal(ctx.unavailableReason, null);

    assert.ok(ctx.proxy);
    assert.equal(ctx.proxy.isProxy, true);
    assert.equal(ctx.proxy.implementation, IMPLEMENTATION);
    assert.equal(ctx.proxy.admin, ADMIN_EOA);

    assert.ok(ctx.admin);
    assert.equal(ctx.admin.owner, OWNER_EOA);
    assert.equal(ctx.admin.pendingOwner, null);
    assert.equal(ctx.admin.ownerKind, 'eoa', 'EOA owner is the eoa-admin-single-key indicator');

    assert.ok(ctx.explorer);
    assert.equal(ctx.explorer.sourceVerified, true);
    assert.equal(ctx.explorer.contractName, 'TransparentUpgradeableProxy');
    assert.equal(ctx.explorer.compilerVersion, 'v0.8.20+commit');
    assert.equal(ctx.explorer.deployerAddress, DEPLOYER);
    assert.equal(ctx.explorer.deploymentTxHash, DEPLOY_TX);
    assert.equal(ctx.explorer.deploymentTimestamp, Number.parseInt(DEPLOY_TIMESTAMP_HEX.slice(2), 16));
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

// ─── EOA: kind is reported, proxy/admin skipped, explorer answers ──────────

test('EOA address: skips proxy/admin RPC calls, explorer reports no creation record', async () => {
  const alchemy = await startAlchemyMock((method, _params) => {
    if (method === 'eth_getCode') return '0x'; // EOA
    return null;
  });
  const etherscan = await startEtherscanMock((action) => {
    if (action === 'getsourcecode') {
      return {
        status: '1',
        message: 'OK',
        result: [
          {
            SourceCode: '',
            ABI: 'Contract source code not verified',
            ContractName: '',
            CompilerVersion: '',
            Proxy: '0',
            Implementation: '',
          },
        ],
      };
    }
    return { status: '0', message: 'No data found', result: 'No data found' };
  });
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });
    const ctx = await loader.getContractContext(EOA_ADDR);

    assert.equal(ctx.kind, 'eoa');
    assert.equal(ctx.availability, 'complete');
    assert.equal(ctx.proxy, null);
    assert.equal(ctx.admin, null);
    assert.ok(ctx.explorer);
    assert.equal(ctx.explorer.sourceVerified, false);
    assert.equal(ctx.explorer.deployerAddress, null);
    assert.equal(ctx.explorer.deploymentTxHash, null);

    // Critical: EOA path made NO proxy/admin/call RPC requests (cost saved).
    assert.equal(alchemy.hits['eth_getStorageAt'] ?? 0, 0);
    assert.equal(alchemy.hits['eth_call'] ?? 0, 0);
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

// ─── Graceful degradation: explorer down → partial availability ─────────────

test('partial: explorer 500 → availability=partial; reason describes Etherscan failure (no key)', async () => {
  const alchemy = await startAlchemyMock((method) => {
    if (method === 'eth_getCode') return '0x6080';
    if (method === 'eth_getStorageAt') return ZERO_STORAGE_SLOT;
    if (method === 'eth_call') return '0x';
    return null;
  });
  const etherscan = await startEtherscanMock(() => 'http-500');
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });
    const ctx = await loader.getContractContext(CONTRACT_ADDR);

    assert.equal(ctx.availability, 'partial');
    assert.equal(ctx.kind, 'contract');
    assert.ok(ctx.proxy);
    assert.ok(ctx.admin);
    assert.equal(ctx.explorer, null);
    assert.ok(ctx.unavailableReason);
    assert.match(ctx.unavailableReason, /Etherscan v2 http-status/);
    // Rubric §12: api key NEVER in unavailableReason.
    assert.equal(ctx.unavailableReason.includes(ETHERSCAN_KEY), false);
    assert.equal(ctx.unavailableReason.includes(ALCHEMY_KEY), false);
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

test('partial: RPC down → availability=partial; explorer still answers', async () => {
  const alchemy = await startAlchemyMock(() => 'http-500');
  const etherscan = await startEtherscanMock((action) => {
    if (action === 'getsourcecode') {
      return {
        status: '1',
        message: 'OK',
        result: [
          {
            SourceCode: 'x',
            ABI: '',
            ContractName: 'C',
            CompilerVersion: 'v',
            Proxy: '0',
            Implementation: '',
          },
        ],
      };
    }
    return { status: '0', message: 'No data found', result: 'No data found' };
  });
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });
    const ctx = await loader.getContractContext(CONTRACT_ADDR);

    assert.equal(ctx.availability, 'partial');
    assert.equal(ctx.kind, 'unknown');
    // When kind is unknown we skipped proxy/admin RPC channels — they're
    // null because the cascade short-circuits on kind failure (no point
    // probing storage if the network is down).
    assert.equal(ctx.proxy, null);
    assert.equal(ctx.admin, null);
    assert.ok(ctx.explorer);
    assert.equal(ctx.explorer.sourceVerified, true);
    assert.ok(ctx.unavailableReason);
    assert.equal(ctx.unavailableReason.includes(ALCHEMY_KEY), false);
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

test('unavailable: both providers down → availability=unavailable', async () => {
  const alchemy = await startAlchemyMock(() => 'http-500');
  const etherscan = await startEtherscanMock(() => 'http-500');
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });
    const ctx = await loader.getContractContext(CONTRACT_ADDR);
    assert.equal(ctx.availability, 'unavailable');
    assert.equal(ctx.kind, 'unknown');
    assert.equal(ctx.proxy, null);
    assert.equal(ctx.admin, null);
    assert.equal(ctx.explorer, null);
    assert.ok(ctx.unavailableReason);
    assert.match(ctx.unavailableReason, /Alchemy RPC/);
    assert.match(ctx.unavailableReason, /Etherscan v2/);
    assert.equal(ctx.unavailableReason.includes(ALCHEMY_KEY), false);
    assert.equal(ctx.unavailableReason.includes(ETHERSCAN_KEY), false);
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

// ─── Cache: same address requested twice → one round-trip ──────────────────

test('per-instance cache: two calls for the same address triggers ONE RPC + ONE explorer fetch', async () => {
  let codeHits = 0;
  let sourceHits = 0;
  const alchemy = await startAlchemyMock((method) => {
    if (method === 'eth_getCode') {
      codeHits += 1;
      return '0x';
    }
    return null;
  });
  const etherscan = await startEtherscanMock((action) => {
    if (action === 'getsourcecode') {
      sourceHits += 1;
      return {
        status: '1',
        message: 'OK',
        result: [{ SourceCode: '', ABI: '', ContractName: '', CompilerVersion: '', Proxy: '0', Implementation: '' }],
      };
    }
    return { status: '0', message: 'No data found', result: 'No data found' };
  });
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });

    const [first, second] = await Promise.all([
      loader.getContractContext(EOA_ADDR),
      loader.getContractContext(EOA_ADDR),
    ]);
    assert.equal(first, second, 'concurrent calls return the same Promise/value');
    assert.equal(codeHits, 1, 'one underlying RPC eth_getCode for two concurrent requests');
    assert.equal(sourceHits, 1, 'one underlying explorer getsourcecode for two concurrent requests');

    // A third, serial call ALSO hits the cache (does NOT re-fetch).
    await loader.getContractContext(EOA_ADDR);
    assert.equal(codeHits, 1);
    assert.equal(sourceHits, 1);
    assert.equal(loader.hasCached(EOA_ADDR), true);
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

// ─── Rate-limited explorer (string envelope) → partial + redaction ─────────

test('explorer rate-limit string envelope → availability=partial; reason mentions rate-limit; key redacted', async () => {
  const alchemy = await startAlchemyMock((method) => {
    if (method === 'eth_getCode') return '0x6080';
    if (method === 'eth_getStorageAt') return ZERO_STORAGE_SLOT;
    if (method === 'eth_call') return '0x';
    return null;
  });
  const etherscan = await startEtherscanMock(() => ({
    status: '0',
    message: 'NOTOK',
    result: `Max calls per sec rate limit reached for apikey=${ETHERSCAN_KEY}`,
  }));
  try {
    const rpc = new AlchemyRpcClient({ apiKey: ALCHEMY_KEY, chain: 'ethereum', baseUrl: alchemy.url });
    const explorer = new EtherscanExplorerClient({ apiKey: ETHERSCAN_KEY, chain: 'ethereum', baseUrl: etherscan.url });
    const loader = new RemoteOnChainContextProvider({ chain: 'ethereum', rpc, explorer });
    const ctx = await loader.getContractContext(CONTRACT_ADDR);
    assert.equal(ctx.availability, 'partial');
    assert.ok(ctx.unavailableReason);
    assert.match(ctx.unavailableReason, /rate-limit/i);
    // Even if a misbehaving provider echoed back our key inside its error
    // message, sanitizeReason MUST redact it.
    assert.equal(ctx.unavailableReason.includes(ETHERSCAN_KEY), false);
  } finally {
    await alchemy.close();
    await etherscan.close();
  }
});

// ─── sanitizeReason direct unit tests (rubric §12 belt + braces) ────────────

test('sanitizeReason redacts `apikey=<token>` patterns from error text', () => {
  const reason = sanitizeReason(new Error('failed: apikey=verysecretkey123456789'));
  assert.match(reason, /apikey=<redacted>/);
  assert.equal(reason.includes('verysecretkey123456789'), false);
});

test('sanitizeReason redacts long hex tokens (key-like, ≥64 chars) but keeps EVM addresses (40)', () => {
  const longHex = 'f'.repeat(96); // looks like a hex key
  const reason = sanitizeReason(new Error(`token ${longHex} bad`));
  assert.match(reason, /<redacted-hex>/);
  assert.equal(reason.includes(longHex), false);

  const evmAddress = `0x${'a'.repeat(40)}`;
  const reasonAddr = sanitizeReason(new Error(`address ${evmAddress} bad`));
  assert.equal(reasonAddr.includes(evmAddress), true, 'EVM addresses (40 hex) are not key-like and pass through');
});

test('sanitizeReason caps the message length at 250 chars', () => {
  const long = 'x'.repeat(1000);
  const reason = sanitizeReason(new Error(long));
  assert.ok(reason.length <= 250);
});
