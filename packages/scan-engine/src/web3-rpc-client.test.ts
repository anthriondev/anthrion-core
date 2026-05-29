import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import {
  ALCHEMY_RPC_BASE_URL_BASE,
  ALCHEMY_RPC_BASE_URL_ETHEREUM,
  AlchemyRpcClient,
  DEFAULT_WEB3_RPC_TIMEOUT_MS,
  EIP1967_ADMIN_SLOT,
  EIP1967_IMPLEMENTATION_SLOT,
  SELECTOR_OWNER,
  Web3RpcError,
  ZERO_STORAGE_SLOT,
  decodeAddressFromStorage,
} from './web3-rpc-client';
import type { ContractAddress } from './web3-types';

const TEST_KEY = 'test-alchemy-key-redact-me';
const CONTRACT_ADDR = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as ContractAddress;
const EOA_ADDR = '0xdeadbeef00000000000000000000000000000001' as ContractAddress;
const IMPL_ADDR = '0xc0de0c0de0c0de0c0de0c0de0c0de0c0de0c0de0' as ContractAddress;

/** Capture-and-respond local server. Test passes a `handler` that drives the
 * response per request body. */
interface ServerHandle {
  url: string;
  /** Each `received` carries the parsed body of one observed request. */
  received: unknown[];
  close: () => Promise<void>;
}

async function startServer(
  handler: (body: unknown, req: IncomingMessage, res: ServerResponse) => void,
): Promise<ServerHandle> {
  const received: unknown[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = raw;
      }
      received.push(parsed);
      handler(parsed, req, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind');
  }
  return {
    url: `http://127.0.0.1:${address.port}`,
    received,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function respondJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function jsonRpcOk(id: number, result: unknown): unknown {
  return { jsonrpc: '2.0', id, result };
}

function jsonRpcErr(id: number, code: number, message: string): unknown {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

// ── Constants + URL construction ────────────────────────────────────────────

test('Alchemy base URLs match the documented Alchemy v2 chain-prefixed shape', () => {
  assert.equal(ALCHEMY_RPC_BASE_URL_ETHEREUM, 'https://eth-mainnet.g.alchemy.com/v2');
  assert.equal(ALCHEMY_RPC_BASE_URL_BASE, 'https://base-mainnet.g.alchemy.com/v2');
});

test('DEFAULT_WEB3_RPC_TIMEOUT_MS is the documented 10s', () => {
  assert.equal(DEFAULT_WEB3_RPC_TIMEOUT_MS, 10_000);
});

test('AlchemyRpcClient: empty apiKey is rejected at construction', () => {
  assert.throws(
    () => new AlchemyRpcClient({ apiKey: '', chain: 'ethereum' }),
    /apiKey is required/,
  );
});

// ── eth_getCode happy path + edge ───────────────────────────────────────────

test('eth_getCode: returns bytecode hex for a contract', async () => {
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number; method: string; params: unknown[] };
    assert.equal(env.method, 'eth_getCode');
    respondJson(res, 200, jsonRpcOk(env.id, '0x60806040523480'));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const code = await client.getCode(CONTRACT_ADDR);
    assert.equal(code, '0x60806040523480');
  } finally {
    await server.close();
  }
});

test('eth_getCode: returns "0x" for an EOA — caller can classify', async () => {
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    respondJson(res, 200, jsonRpcOk(env.id, '0x'));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    assert.equal(await client.getCode(EOA_ADDR), '0x');
  } finally {
    await server.close();
  }
});

// ── eth_getStorageAt + normalisation ────────────────────────────────────────

test('eth_getStorageAt: returns the normalised 32-byte slot', async () => {
  const slotValue = `0x000000000000000000000000${IMPL_ADDR.slice(2)}`;
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number; params: unknown[] };
    assert.deepEqual(env.params[1], EIP1967_IMPLEMENTATION_SLOT);
    respondJson(res, 200, jsonRpcOk(env.id, slotValue));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const value = await client.getStorageAt(CONTRACT_ADDR, EIP1967_IMPLEMENTATION_SLOT);
    assert.equal(value, slotValue.toLowerCase());
    // decodeAddressFromStorage round-trips it back to the implementation.
    assert.equal(decodeAddressFromStorage(value), IMPL_ADDR);
  } finally {
    await server.close();
  }
});

test('eth_getStorageAt: zero-slot returns the canonical ZERO_STORAGE_SLOT and decodes to null', async () => {
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    respondJson(res, 200, jsonRpcOk(env.id, ZERO_STORAGE_SLOT));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const value = await client.getStorageAt(CONTRACT_ADDR, EIP1967_ADMIN_SLOT);
    assert.equal(value, ZERO_STORAGE_SLOT);
    assert.equal(decodeAddressFromStorage(value), null);
  } finally {
    await server.close();
  }
});

test('eth_getStorageAt: left-pads a short return to 32 bytes', async () => {
  // Alchemy / Geth sometimes returns short hex for unwritten slots.
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    respondJson(res, 200, jsonRpcOk(env.id, '0x0'));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const value = await client.getStorageAt(CONTRACT_ADDR, EIP1967_ADMIN_SLOT);
    assert.equal(value, ZERO_STORAGE_SLOT);
  } finally {
    await server.close();
  }
});

// ── eth_call + revert ───────────────────────────────────────────────────────

test('eth_call: returns return-data for a working accessor', async () => {
  const ownerSlot = `0x000000000000000000000000${IMPL_ADDR.slice(2)}`;
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number; params: unknown[] };
    const call = env.params[0] as { to: string; data: string };
    assert.equal(call.data, SELECTOR_OWNER);
    respondJson(res, 200, jsonRpcOk(env.id, ownerSlot));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.call(CONTRACT_ADDR, SELECTOR_OWNER);
    assert.equal(result, ownerSlot.toLowerCase());
  } finally {
    await server.close();
  }
});

test('eth_call: a JSON-RPC error response degrades to "0x" (treated as "not exposed")', async () => {
  // A function that doesn't exist on the contract reverts; the RPC node
  // returns a JSON-RPC error. Our client treats that as "method not exposed"
  // so the caller doesn't fall back to availability=partial on EVERY contract
  // without an `owner()` (most contracts don't have it).
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    respondJson(res, 200, jsonRpcErr(env.id, 3, 'execution reverted'));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.call(CONTRACT_ADDR, SELECTOR_OWNER);
    assert.equal(result, '0x');
  } finally {
    await server.close();
  }
});

// ── eth_getTransactionByHash / eth_getBlockByNumber ─────────────────────────

test('getTransactionBlockNumber: returns the hex block number from the tx response', async () => {
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    respondJson(res, 200, jsonRpcOk(env.id, { blockNumber: '0x1234', from: '0xabc' }));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const blockNumber = await client.getTransactionBlockNumber(`0x${'aa'.repeat(32)}`);
    assert.equal(blockNumber, '0x1234');
  } finally {
    await server.close();
  }
});

test('getBlockTimestamp: returns decimal seconds parsed from hex timestamp', async () => {
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    // 0x60d33333 = 1624471347 (some 2021-ish timestamp)
    respondJson(res, 200, jsonRpcOk(env.id, { timestamp: '0x60d33333', number: '0x1234' }));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const ts = await client.getBlockTimestamp('0x1234');
    assert.equal(ts, 0x60d33333);
  } finally {
    await server.close();
  }
});

// ── Failure modes — rubric §12: API key NEVER appears in error messages ─────

test('http error: non-2xx response → Web3RpcError; api key NEVER in message', async () => {
  const server = await startServer((_body, _req, res) => {
    respondJson(res, 500, { error: 'internal server error' });
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3RpcError);
        assert.equal(err.kind, 'http-status');
        assert.equal(err.status, 500);
        assert.equal(err.message.includes(TEST_KEY), false, 'api key must not leak into error message');
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('malformed response: non-JSON body → Web3RpcError(malformed-response)', async () => {
  const server = await startServer((_body, _req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('not json {');
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3RpcError);
        assert.equal(err.kind, 'malformed-response');
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('timeout: a slow server triggers Web3RpcError(timeout) — api key not leaked', async () => {
  const server = await startServer((_body, _req, _res) => {
    // Never respond — hang.
  });
  try {
    const client = new AlchemyRpcClient({
      apiKey: TEST_KEY,
      chain: 'ethereum',
      baseUrl: server.url,
      timeoutMs: 50,
    });
    await assert.rejects(
      () => client.getCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3RpcError);
        assert.equal(err.kind, 'timeout');
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('rpc error from getStorageAt (not eth_call) propagates as Web3RpcError(rpc-error)', async () => {
  // Unlike eth_call (which softens revert to "0x"), eth_getStorageAt MUST
  // propagate RPC errors so the loader can record the proxy channel failure.
  const server = await startServer((body, _req, res) => {
    const env = body as { id: number };
    respondJson(res, 200, jsonRpcErr(env.id, -32000, 'some internal error'));
  });
  try {
    const client = new AlchemyRpcClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getStorageAt(CONTRACT_ADDR, EIP1967_IMPLEMENTATION_SLOT),
      (err) => {
        assert.ok(err instanceof Web3RpcError);
        assert.equal(err.kind, 'rpc-error');
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});
