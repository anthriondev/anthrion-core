import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test } from 'node:test';

import {
  DEFAULT_WEB3_EXPLORER_TIMEOUT_MS,
  ETHERSCAN_V2_API_BASE_URL,
  EtherscanExplorerClient,
  Web3ExplorerError,
  etherscanChainId,
} from './web3-explorer-client';
import type { ContractAddress } from './web3-types';

const TEST_KEY = 'test-etherscan-key-redact-me';
const CONTRACT_ADDR = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as ContractAddress;
const DEPLOYER = '0xfeedfacefeedfacefeedfacefeedfacefeedface' as ContractAddress;

interface ServerHandle {
  url: string;
  /** All inbound request URLs (path + query). */
  requestedUrls: string[];
  close: () => Promise<void>;
}

async function startServer(
  handler: (params: URLSearchParams, req: IncomingMessage, res: ServerResponse) => void,
): Promise<ServerHandle> {
  const requestedUrls: string[] = [];
  const server: Server = createServer((req, res) => {
    requestedUrls.push(req.url ?? '');
    const url = new URL(req.url ?? '/', 'http://placeholder');
    handler(url.searchParams, req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind');
  }
  return {
    url: `http://127.0.0.1:${address.port}/v2/api`,
    requestedUrls,
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

// ── Constants ───────────────────────────────────────────────────────────────

test('ETHERSCAN_V2_API_BASE_URL matches the documented unified-v2 endpoint', () => {
  assert.equal(ETHERSCAN_V2_API_BASE_URL, 'https://api.etherscan.io/v2/api');
});

test('DEFAULT_WEB3_EXPLORER_TIMEOUT_MS is the documented 10s', () => {
  assert.equal(DEFAULT_WEB3_EXPLORER_TIMEOUT_MS, 10_000);
});

test('etherscanChainId maps the two supported mainnets', () => {
  assert.equal(etherscanChainId('ethereum'), 1);
  assert.equal(etherscanChainId('base'), 8453);
});

test('EtherscanExplorerClient: empty apiKey is rejected at construction', () => {
  assert.throws(
    () => new EtherscanExplorerClient({ apiKey: '', chain: 'ethereum' }),
    /apiKey is required/,
  );
});

// ── getSourceCode happy path: verified contract ────────────────────────────

test('getSourceCode: verified contract returns name + compiler + verified=true', async () => {
  const server = await startServer((params, _req, res) => {
    assert.equal(params.get('chainid'), '1');
    assert.equal(params.get('module'), 'contract');
    assert.equal(params.get('action'), 'getsourcecode');
    assert.equal(params.get('apikey'), TEST_KEY);
    respondJson(res, 200, {
      status: '1',
      message: 'OK',
      result: [
        {
          SourceCode: 'contract Foo {}',
          ABI: '[]',
          ContractName: 'FiatTokenV2_1',
          CompilerVersion: 'v0.6.12+commit.27d51765',
          Proxy: '0',
          Implementation: '',
        },
      ],
    });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.getSourceCode(CONTRACT_ADDR);
    assert.equal(result.verified, true);
    assert.equal(result.contractName, 'FiatTokenV2_1');
    assert.equal(result.compilerVersion, 'v0.6.12+commit.27d51765');
    assert.equal(result.isProxy, false);
    assert.equal(result.implementation, null);
  } finally {
    await server.close();
  }
});

test('getSourceCode: verified proxy with implementation address', async () => {
  const impl = '0xc0de0c0de0c0de0c0de0c0de0c0de0c0de0c0de0';
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 200, {
      status: '1',
      message: 'OK',
      result: [
        {
          SourceCode: 'contract Proxy {}',
          ABI: '[]',
          ContractName: 'TransparentUpgradeableProxy',
          CompilerVersion: 'v0.8.20+commit',
          Proxy: '1',
          Implementation: impl,
        },
      ],
    });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.getSourceCode(CONTRACT_ADDR);
    assert.equal(result.isProxy, true);
    assert.equal(result.implementation, impl);
  } finally {
    await server.close();
  }
});

test('getSourceCode: unverified contract returns verified=false + nulls (NOT an error)', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 200, {
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
    });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.getSourceCode(CONTRACT_ADDR);
    assert.equal(result.verified, false);
    assert.equal(result.contractName, null);
    assert.equal(result.compilerVersion, null);
    assert.equal(result.isProxy, false);
    assert.equal(result.implementation, null);
  } finally {
    await server.close();
  }
});

test('getSourceCode: chain=base sends chainid=8453', async () => {
  const server = await startServer((params, _req, res) => {
    assert.equal(params.get('chainid'), '8453');
    respondJson(res, 200, {
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
    });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'base', baseUrl: server.url });
    await client.getSourceCode(CONTRACT_ADDR);
  } finally {
    await server.close();
  }
});

// ── getContractCreation happy path + "no data" ─────────────────────────────

test('getContractCreation: returns creator + txHash', async () => {
  const txHash = `0x${'aa'.repeat(32)}`;
  const server = await startServer((params, _req, res) => {
    assert.equal(params.get('action'), 'getcontractcreation');
    assert.equal(params.get('contractaddresses'), CONTRACT_ADDR);
    respondJson(res, 200, {
      status: '1',
      message: 'OK',
      result: [{ contractAddress: CONTRACT_ADDR, contractCreator: DEPLOYER, txHash }],
    });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.getContractCreation(CONTRACT_ADDR);
    assert.ok(result);
    assert.equal(result.contractCreator, DEPLOYER);
    assert.equal(result.txHash, txHash);
  } finally {
    await server.close();
  }
});

test('getContractCreation: "No data found" returns null (EOA / pre-genesis — NOT an error)', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 200, { status: '0', message: 'No data found', result: 'No data found' });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    const result = await client.getContractCreation(CONTRACT_ADDR);
    assert.equal(result, null);
  } finally {
    await server.close();
  }
});

// ── Failure modes — rubric §12: api key NEVER appears in error messages ────

test('rate-limited (string envelope): throws Web3ExplorerError(rate-limited)', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 200, {
      status: '0',
      message: 'NOTOK',
      result: 'Max calls per sec rate limit reached, please try again',
    });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getSourceCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3ExplorerError);
        assert.equal(err.kind, 'rate-limited');
        assert.equal(err.message.includes(TEST_KEY), false, 'api key must not leak into error message');
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('rate-limited (HTTP 429): throws Web3ExplorerError(rate-limited) with status 429', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 429, { error: 'too many requests' });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getSourceCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3ExplorerError);
        assert.equal(err.kind, 'rate-limited');
        assert.equal(err.status, 429);
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('invalid api key: surfaces as Web3ExplorerError(invalid-api-key); key NEVER in message', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 200, { status: '0', message: 'NOTOK', result: 'Invalid API Key' });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getSourceCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3ExplorerError);
        assert.equal(err.kind, 'invalid-api-key');
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('http 5xx: surfaces as Web3ExplorerError(http-status); api key not in message', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 503, { error: 'service unavailable' });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getContractCreation(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3ExplorerError);
        assert.equal(err.kind, 'http-status');
        assert.equal(err.status, 503);
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('timeout: a hanging server triggers Web3ExplorerError(timeout); api key not in message', async () => {
  const server = await startServer((_params, _req, _res) => {
    /* never respond */
  });
  try {
    const client = new EtherscanExplorerClient({
      apiKey: TEST_KEY,
      chain: 'ethereum',
      baseUrl: server.url,
      timeoutMs: 50,
    });
    await assert.rejects(
      () => client.getSourceCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3ExplorerError);
        assert.equal(err.kind, 'timeout');
        assert.equal(err.message.includes(TEST_KEY), false);
        return true;
      },
    );
  } finally {
    await server.close();
  }
});

test('malformed shape: response is JSON but does not match the v2 envelope → malformed-response', async () => {
  const server = await startServer((_params, _req, res) => {
    respondJson(res, 200, { foo: 'bar' });
  });
  try {
    const client = new EtherscanExplorerClient({ apiKey: TEST_KEY, chain: 'ethereum', baseUrl: server.url });
    await assert.rejects(
      () => client.getSourceCode(CONTRACT_ADDR),
      (err) => {
        assert.ok(err instanceof Web3ExplorerError);
        assert.equal(err.kind, 'malformed-response');
        return true;
      },
    );
  } finally {
    await server.close();
  }
});
