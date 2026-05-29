import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test, before, after } from 'node:test';

import { chromium, type Browser, type BrowserContext } from 'playwright';

import { DEFAULT_LAUNCH_ARGS } from './web-scan';
import { buildSyntheticProviderScript, CAPTURE_GLOBAL_KEY } from './web3-provider-script';
import { PlaywrightWeb3DAppTarget, readCapturedWalletRequests } from './web3-target';

/**
 * End-to-end target tests for `PlaywrightWeb3DAppTarget` (T-A3.2 DoD).
 *
 * Real headless Chromium navigates to a real local HTTP server serving a tiny
 * synthetic dApp page. The synthetic provider script is installed via
 * `page.addInitScript` BEFORE navigation (the contract `PlaywrightWeb3DAppTarget`
 * expects). The dApp page then calls `window.ethereum.request(...)` against a
 * real `window.ethereum` (the synthetic provider), the harvester reads the
 * capture array off the page, and the target exposes wallet requests +
 * referenced contracts + the no-interactive-flow signal — without any real
 * wallet, real chain, real RPC, or signature recovery.
 *
 * Complements `web3-provider-script.test.ts` (which exercises the provider
 * surface in isolation in Node) by proving the full Playwright stack works.
 */

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

async function startServer(handler: Handler): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('test server failed to bind a port');
  }
  const url = `http://127.0.0.1:${address.port}/`;
  const close = (): Promise<void> => {
    server.closeAllConnections();
    return new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  };
  return { url, close };
}

function htmlResponse(res: ServerResponse, body: string): void {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(body);
}

const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const RANDOM_DOM_CONTRACT = '0xababababababababababababababababababcdef';

/**
 * A tiny dApp page: on `DOMContentLoaded`, it asks for accounts, queries the
 * chain id, calls a contract, and signs typed data — the exact pattern modern
 * wallet libraries (wagmi, RainbowKit) trigger in their initial flow. Errors
 * inside the dApp surface in the body for observability but never throw out.
 */
function synthDappHtml(extraDomContract: string = RANDOM_DOM_CONTRACT): string {
  return `<!doctype html><html><head><title>Synth dApp</title></head>
<body>
  <p>dApp under test. <a href="https://etherscan.io/address/${extraDomContract}">contract</a></p>
  <pre id="log"></pre>
  <script>
    (async () => {
      const log = document.getElementById('log');
      function append(line) { log.textContent += line + '\\n'; }
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        append('accounts:' + JSON.stringify(accounts));
        const chainId = await window.ethereum.request({ method: 'eth_chainId' });
        append('chainId:' + chainId);
        await window.ethereum.request({ method: 'eth_call', params: [{ to: '${USDC}', data: '0x' }, 'latest'] });
        append('eth_call:ok');
        await window.ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [accounts[0], { domain: { verifyingContract: '${USDC}', chainId: 1 }, message: {}, types: {}, primaryType: 'Permit' }],
        });
        append('signTypedData:ok');
      } catch (err) {
        append('error:' + (err && err.message ? err.message : String(err)));
      }
    })();
  </script>
</body></html>`;
}

let browser: Browser;
before(async () => {
  browser = await chromium.launch({ headless: true, args: [...DEFAULT_LAUNCH_ARGS] });
});
after(async () => {
  await browser.close();
});

test('PlaywrightWeb3DAppTarget captures the dApp wallet flow end-to-end', async () => {
  const server = await startServer((_req, res) => htmlResponse(res, synthDappHtml()));
  let ctx: BrowserContext | undefined;
  try {
    ctx = await browser.newContext();
    await ctx.addInitScript(buildSyntheticProviderScript('ethereum'));
    const page = await ctx.newPage();
    const response = await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    if (response === null) {
      assert.fail('page did not produce a response');
    }
    // Wait until the in-page script writes the final marker, so we know the
    // wallet flow has finished before harvesting.
    await page.waitForFunction(
      `document.getElementById('log') && document.getElementById('log').textContent.includes('signTypedData:ok')`,
      undefined,
      { timeout: 10_000 },
    );

    const target = new PlaywrightWeb3DAppTarget(page, response, server.url, 'ethereum');
    assert.equal(target.chain, 'ethereum');

    const requests = await target.walletRequests();
    const methods = requests.map((r) => r.method);
    assert.ok(methods.includes('eth_requestAccounts'), `expected eth_requestAccounts in ${methods.join(',')}`);
    assert.ok(methods.includes('eth_chainId'), `expected eth_chainId in ${methods.join(',')}`);
    assert.ok(methods.includes('eth_call'), `expected eth_call in ${methods.join(',')}`);
    assert.ok(methods.includes('eth_signTypedData_v4'), `expected eth_signTypedData_v4 in ${methods.join(',')}`);

    assert.equal(await target.observedInteractiveFlow(), true);

    const refs = await target.referencedContracts();
    const refAddrs = new Set(refs.map((r) => r.address));
    assert.ok(refAddrs.has(USDC), 'expected USDC harvested from eth_call/eth_signTypedData_v4');
    assert.ok(refAddrs.has(RANDOM_DOM_CONTRACT), 'expected DOM-referenced contract to be harvested too');

    // Provenance for USDC must be the stronger wallet-request, since it was
    // observed in both wallet calls AND (potentially) the DOM/etherscan link.
    const usdcRef = refs.find((r) => r.address === USDC);
    assert.equal(usdcRef?.origin, 'wallet-request');

    // Memoization: second call returns the same array reference / same data.
    const requestsAgain = await target.walletRequests();
    assert.equal(requestsAgain, requests, 'walletRequests must be memoized across calls');
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});

test('PlaywrightWeb3DAppTarget emits observedInteractiveFlow=false when the dApp asks for nothing', async () => {
  const server = await startServer((_req, res) =>
    htmlResponse(res, '<!doctype html><html><body><p>landing page only</p></body></html>'),
  );
  let ctx: BrowserContext | undefined;
  try {
    ctx = await browser.newContext();
    await ctx.addInitScript(buildSyntheticProviderScript('base'));
    const page = await ctx.newPage();
    const response = await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    if (response === null) {
      assert.fail('page did not produce a response');
    }
    const target = new PlaywrightWeb3DAppTarget(page, response, server.url, 'base');
    assert.equal(await target.observedInteractiveFlow(), false);
    assert.equal((await target.walletRequests()).length, 0);
    assert.equal((await target.referencedContracts()).length, 0);
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});

test('readCapturedWalletRequests returns [] when the page has no capture global', async () => {
  const server = await startServer((_req, res) => htmlResponse(res, '<!doctype html><html><body>nope</body></html>'));
  let ctx: BrowserContext | undefined;
  try {
    // NOTE: NOT installing the synthetic provider — so the capture global is
    // missing. The harvester must treat that as zero requests (honest signal),
    // never as a thrown error.
    ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    const requests = await readCapturedWalletRequests(page);
    assert.equal(requests.length, 0);
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});

test('readCapturedWalletRequests returns [] when the capture global is malformed', async () => {
  // A page that defines the capture global as a malformed value — the
  // harvester must Zod-reject and degrade to zero requests, never crash.
  const server = await startServer((_req, res) =>
    htmlResponse(
      res,
      `<!doctype html><html><body>
        <script>
          window['${CAPTURE_GLOBAL_KEY}'] = [{ this: 'is', not: 'a wallet request' }];
        </script>
      </body></html>`,
    ),
  );
  let ctx: BrowserContext | undefined;
  try {
    ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    const requests = await readCapturedWalletRequests(page);
    assert.equal(requests.length, 0);
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});

test('a Sprint A1 sub-agent rubric §11 check — provider script contains no signing or key code', () => {
  const script = buildSyntheticProviderScript('ethereum');
  // The synthetic provider MUST NOT contain any cryptographic / key-handling
  // primitives. Real signing would imply a private key exists somewhere; the
  // entire scan family is built on the contract that no key exists.
  for (const banned of [
    'privateKey',
    'PrivateKey',
    'secp256k1',
    'recoverAddress',
    'recoverPublicKey',
    'signMessage',
    'eip191',
  ]) {
    assert.equal(script.includes(banned), false, `synthetic provider script must not reference \`${banned}\``);
  }
});
