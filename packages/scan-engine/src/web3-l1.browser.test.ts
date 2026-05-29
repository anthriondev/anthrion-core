import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test, before, after } from 'node:test';

import { chromium, type Browser, type BrowserContext } from 'playwright';

import { DEFAULT_LAUNCH_ARGS } from './web-scan';
import { PlaywrightWeb3DAppTarget } from './web3-target';
import { buildSyntheticProviderScript } from './web3-provider-script';
import { runWeb3Layer1 } from './web3-l1';
import { MAX_UINT256_HEX_LOWER, PERMIT2_CONTRACT_ADDRESS } from './web3-l1-probe';

/**
 * Chromium end-to-end tests for the L1 runner (T-A3.3).
 *
 * Proves the full pipeline works:
 *   synthetic EIP-1193 provider → page capture array → harvester →
 *   `Web3DAppTarget` → `runWeb3Layer1` → Zod-valid `Finding`s.
 *
 * Complements `web3-l1.test.ts` (pure-Node runner contract) and
 * `web3-l1-probes.test.ts` (per-probe structural detection). Tests here
 * deliberately exercise the SAME paths the worker (T-A3.7) will run in
 * production: real `page.addInitScript`, real `page.goto`, real
 * `page.evaluate` reading the capture global off the loaded page.
 *
 * Each test starts its own local HTTP server + Browser context for isolation.
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
const SPENDER = '0xdeadbeef00000000000000000000000000000001';
const DELEGATE = '0xc0de00000000000000000000000000000000beef';
const APPROVE_SELECTOR = '0x095ea7b3';

/** Render a phishing-flavoured dApp page. The page fires, in order:
 *  1. `eth_requestAccounts` (benign — needed so the dApp completes wallet detection)
 *  2. `eth_sendTransaction` with `approve(spender, max_uint256)` calldata
 *  3. `eth_signTypedData_v1` (legacy schemaless format)
 *  4. `eth_sendTransaction` with `authorizationList` (EIP-7702 SetCode)
 *
 * Writes `done` into `#log` once every step has completed so the test can
 * wait for the full flow before harvesting.
 */
function phishingDappHtml(): string {
  const approveData = `${APPROVE_SELECTOR}${'0'.repeat(24)}${SPENDER.slice(2)}${MAX_UINT256_HEX_LOWER}`;
  return `<!doctype html><html><head><title>Phishing dApp</title></head>
<body>
  <pre id="log"></pre>
  <script>
    (async () => {
      const log = document.getElementById('log');
      function append(line) { log.textContent += line + '\\n'; }
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        append('step1:' + accounts.length);
        await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{ to: ${JSON.stringify(USDC)}, data: ${JSON.stringify(approveData)} }],
        });
        append('step2');
        await window.ethereum.request({
          method: 'eth_signTypedData_v1',
          params: [
            [{ type: 'string', name: 'msg', value: 'hi' }],
            accounts[0],
          ],
        });
        append('step3');
        await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{
            to: ${JSON.stringify(USDC)},
            type: '0x4',
            authorizationList: [{ address: ${JSON.stringify(DELEGATE)}, chainId: '0x1', nonce: '0x0' }],
          }],
        });
        append('done');
      } catch (err) {
        append('error:' + (err && err.message ? err.message : String(err)));
      }
    })();
  </script>
</body></html>`;
}

function permit2DappHtml(): string {
  // Build a Permit2 PermitSingle payload with max_uint160 amount, signed via
  // eth_signTypedData_v4 — the production Uniswap flow.
  const maxUint160Hex = `0x${'f'.repeat(40)}`;
  const typedData = {
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2_CONTRACT_ADDRESS },
    primaryType: 'PermitSingle',
    types: { PermitSingle: [{ name: 'spender', type: 'address' }] },
    message: {
      details: { token: USDC, amount: maxUint160Hex, expiration: 9999999999, nonce: 0 },
      spender: SPENDER,
      sigDeadline: 9999999999,
    },
  };
  return `<!doctype html><html><head><title>Permit2 dApp</title></head>
<body>
  <pre id="log"></pre>
  <script>
    (async () => {
      const log = document.getElementById('log');
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        await window.ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [accounts[0], ${JSON.stringify(typedData)}],
        });
        log.textContent = 'done';
      } catch (err) {
        log.textContent = 'error:' + (err && err.message ? err.message : String(err));
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

test('runWeb3Layer1 end-to-end: phishing dApp triggers 3 findings (approve-max, typed-data-v1, EIP-7702)', async () => {
  const server = await startServer((_req, res) => htmlResponse(res, phishingDappHtml()));
  let ctx: BrowserContext | undefined;
  try {
    ctx = await browser.newContext();
    await ctx.addInitScript(buildSyntheticProviderScript('ethereum'));
    const page = await ctx.newPage();
    const response = await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    assert.ok(response, 'navigation produced a response');
    // Wait for the in-page script to finish all four steps.
    await page.waitForFunction(
      `document.getElementById('log') && document.getElementById('log').textContent.includes('done')`,
      undefined,
      { timeout: 10_000 },
    );
    const target = new PlaywrightWeb3DAppTarget(page, response, server.url, 'ethereum');
    const report = await runWeb3Layer1(target);

    assert.equal(report.outcome, 'vulnerable');
    assert.equal(report.observedInteractiveFlow, true);
    const cats = new Set(report.findings.map((f) => f.category));
    assert.ok(cats.has('wallet-approval-phishing'), `expected wallet-approval-phishing in ${[...cats].join(',')}`);
    assert.ok(cats.has('deceptive-typed-data-signature'), `expected deceptive-typed-data-signature in ${[...cats].join(',')}`);
    assert.ok(cats.has('eip-7702-set-code-delegation'), `expected eip-7702-set-code-delegation in ${[...cats].join(',')}`);
    // EIP-7702 is Critical regardless; the other two are High / Medium.
    const eip7702 = report.findings.find((f) => f.category === 'eip-7702-set-code-delegation');
    assert.equal(eip7702?.severity, 'Critical');
    // Captured wallet-request count is reported truthfully (at least the 4 we triggered).
    assert.ok(report.stats.walletRequestCount >= 4, `expected ≥4 captured requests, got ${report.stats.walletRequestCount}`);
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});

test('runWeb3Layer1 end-to-end: Permit2 PermitSingle with max amount → permit2-mass-approval finding', async () => {
  const server = await startServer((_req, res) => htmlResponse(res, permit2DappHtml()));
  let ctx: BrowserContext | undefined;
  try {
    ctx = await browser.newContext();
    await ctx.addInitScript(buildSyntheticProviderScript('ethereum'));
    const page = await ctx.newPage();
    const response = await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    assert.ok(response, 'navigation produced a response');
    await page.waitForFunction(
      `document.getElementById('log') && document.getElementById('log').textContent === 'done'`,
      undefined,
      { timeout: 10_000 },
    );
    const target = new PlaywrightWeb3DAppTarget(page, response, server.url, 'ethereum');
    const report = await runWeb3Layer1(target);

    assert.equal(report.outcome, 'vulnerable');
    const permit2 = report.findings.find((f) => f.category === 'permit2-mass-approval');
    assert.ok(permit2, `expected permit2-mass-approval finding, got ${report.findings.map((f) => f.category).join(',')}`);
    assert.equal(permit2.severity, 'High');
    assert.equal(permit2.evidence.metadata?.token, USDC);
    assert.equal(permit2.evidence.metadata?.spender, SPENDER);
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});

test('runWeb3Layer1 end-to-end: landing-only page → no-interactive-flow-observed', async () => {
  const server = await startServer((_req, res) =>
    htmlResponse(res, '<!doctype html><html><body><p>landing page; no wallet flow</p></body></html>'),
  );
  let ctx: BrowserContext | undefined;
  try {
    ctx = await browser.newContext();
    await ctx.addInitScript(buildSyntheticProviderScript('base'));
    const page = await ctx.newPage();
    const response = await page.goto(server.url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    assert.ok(response, 'navigation produced a response');
    const target = new PlaywrightWeb3DAppTarget(page, response, server.url, 'base');
    const report = await runWeb3Layer1(target);
    assert.equal(report.outcome, 'no-interactive-flow-observed');
    assert.equal(report.observedInteractiveFlow, false);
    assert.equal(report.findings.length, 0);
    assert.equal(report.chain, 'base');
    // Every probe is `not-executed` (the L1 honesty rule). We never run probes
    // when there's nothing to inspect — they would otherwise be "clean" lies.
    for (const result of report.results) {
      assert.equal(result.status, 'not-executed');
    }
  } finally {
    if (ctx !== undefined) await ctx.close();
    await server.close();
  }
});
