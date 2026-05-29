import assert from 'node:assert/strict';
import { test } from 'node:test';

import { owaspWeb3CategorySchema } from './category';
import {
  MAX_UINT160_HEX_LOWER,
  MAX_UINT256_HEX_LOWER,
  PERMIT2_CONTRACT_ADDRESS,
  SELECTOR_ERC20_APPROVE,
  SELECTOR_SET_APPROVAL_FOR_ALL,
  type Web3L1Probe,
} from './web3-l1-probe';
import { WEB3_L1_PROBES } from './web3-l1-probes';
import type { Web3DAppTarget } from './web3-target';
import type { WalletRequest, ReferencedContract } from './web3-types';
import type { Web3Chain } from './config';

/**
 * Node-side unit tests for the six L1 probes (T-A3.3).
 *
 * Each probe is fed a hand-crafted `Web3DAppTarget` stub with a curated
 * `WalletRequest[]` and asserts what the probe does and does NOT detect.
 * No Chromium — purely the structural-detection logic of each probe. The
 * matching browser-driven end-to-end test (`web3-l1.test.ts`) proves the
 * full pipeline (synthetic provider → capture → harvest → probe → Finding).
 *
 * Stub shape: `Web3DAppTarget` extends `PageContext`, so the stub provides
 * trivial implementations of every PageContext method. L1 probes only touch
 * `chain` and `walletRequests()`; the other accessors exist to satisfy the
 * type contract and would crash a probe that calls them (defensive — keeps
 * us honest that L1 probes really are wallet-request-only).
 */

function createStubTarget(input: {
  chain: Web3Chain;
  walletRequests: readonly WalletRequest[];
  referencedContracts?: readonly ReferencedContract[];
}): Web3DAppTarget {
  const fail = (name: string): never => {
    throw new Error(`stub Web3DAppTarget: L1 probe touched \`${name}\` — L1 should be wallet-request-only`);
  };
  return {
    chain: input.chain,
    requestedUrl: 'https://stub.invalid/',
    finalUrl: 'https://stub.invalid/',
    status: 200,
    responseHeaders: {},
    isHttps: true,
    cookies: () => fail('cookies()'),
    securityDetails: () => fail('securityDetails()'),
    html: () => fail('html()'),
    resources: () => fail('resources()'),
    walletRequests: () => Promise.resolve(input.walletRequests),
    referencedContracts: () => Promise.resolve(input.referencedContracts ?? []),
    observedInteractiveFlow: () => Promise.resolve(input.walletRequests.length > 0),
  };
}

function probeById(id: string): Web3L1Probe {
  const probe = WEB3_L1_PROBES.find((p) => p.id === id);
  if (probe === undefined) {
    throw new Error(`probe not found: ${id}`);
  }
  return probe;
}

/** Build a `WalletRequest` with required boilerplate filled in. */
function req(method: string, params: unknown, sequence = 0): WalletRequest {
  return {
    sequence,
    method,
    params,
    timestamp: 0,
    outcome: { kind: 'resolved', result: null },
  };
}

/** Pad a 20-byte address into a 32-byte EVM ABI slot (right-aligned, lower-cased). */
function abiAddress(addr: string): string {
  const body = addr.toLowerCase().replace(/^0x/, '');
  if (body.length !== 40) throw new Error(`bad address: ${addr}`);
  return '0'.repeat(24) + body;
}

/** Build calldata for `approve(spender, amount)` given the lower-case hex
 * amount (no `0x` prefix, exactly 64 chars). */
function approveCalldata(spender: string, amountHex: string): string {
  if (amountHex.length !== 64) throw new Error(`amountHex must be 64 chars: ${amountHex}`);
  return `${SELECTOR_ERC20_APPROVE}${abiAddress(spender)}${amountHex}`;
}

function setApprovalForAllCalldata(operator: string, approved: boolean): string {
  const flag = approved ? '0'.repeat(63) + '1' : '0'.repeat(64);
  return `${SELECTOR_SET_APPROVAL_FOR_ALL}${abiAddress(operator)}${flag}`;
}

const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const SPENDER = '0xdeadbeef00000000000000000000000000000001';
const TOKEN = '0xbeefcafe00000000000000000000000000000002';

// ─── 0. Curated probe set integrity ─────────────────────────────────────────

test('WEB3_L1_PROBES contains exactly the 6 L1 slugs from owaspWeb3CategorySchema, in order', () => {
  const expected = [
    'wallet-approval-phishing',
    'deceptive-typed-data-signature',
    'personal-sign-payload-smell',
    'eip-7702-set-code-delegation',
    'mismatched-chainid-request',
    'permit2-mass-approval',
  ] as const;
  assert.equal(WEB3_L1_PROBES.length, expected.length, '6 probes total');
  const actualCategories = WEB3_L1_PROBES.map((p) => p.category);
  assert.deepEqual(actualCategories, expected);
  // Every probe id and category MUST be unique.
  const ids = new Set(WEB3_L1_PROBES.map((p) => p.id));
  assert.equal(ids.size, WEB3_L1_PROBES.length, 'probe ids unique');
  const cats = new Set(WEB3_L1_PROBES.map((p) => p.category));
  assert.equal(cats.size, WEB3_L1_PROBES.length, 'probe categories unique');
  // Every category MUST validate against the L1 slug enum.
  for (const probe of WEB3_L1_PROBES) {
    assert.doesNotThrow(() => owaspWeb3CategorySchema.parse(probe.category), `category ${probe.category} must be a valid Web3 enum slug`);
  }
});

test('WEB3_L1_PROBES probes are frozen (immutable)', () => {
  assert.ok(Object.isFrozen(WEB3_L1_PROBES));
});

// ─── 1. wallet-approval-phishing ────────────────────────────────────────────

test('wallet-approval-phishing: flags ERC-20 approve(max_uint256)', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: approveCalldata(SPENDER, MAX_UINT256_HEX_LOWER) }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  const det = detections[0];
  assert.ok(det);
  assert.equal(det.walletRequestSequence, 0);
  assert.equal(det.walletRequestMethod, 'eth_sendTransaction');
  assert.equal(det.metadata?.pattern, 'erc20-approve-max');
  assert.equal(det.metadata?.spender, SPENDER);
  assert.equal(det.metadata?.token, USDC);
});

test('wallet-approval-phishing: does NOT flag a bounded approve amount', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  // approve(spender, 1000) — non-max, not flagged.
  const boundedAmount = '0'.repeat(60) + '03e8'; // decimal 1000 in last 4 bytes
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: approveCalldata(SPENDER, boundedAmount) }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('wallet-approval-phishing: flags setApprovalForAll(operator, true)', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: setApprovalForAllCalldata(SPENDER, true) }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'set-approval-for-all-true');
  assert.equal(detections[0]?.metadata?.operator, SPENDER);
});

test('wallet-approval-phishing: does NOT flag setApprovalForAll(operator, false)', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: setApprovalForAllCalldata(SPENDER, false) }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('wallet-approval-phishing: flags EIP-2612 Permit with max value (hex string)', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'USD Coin', chainId: 1, verifyingContract: USDC },
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          primaryType: 'Permit',
          message: { spender: SPENDER, value: `0x${MAX_UINT256_HEX_LOWER}` },
        },
      ], 7),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.walletRequestSequence, 7);
  assert.equal(detections[0]?.metadata?.pattern, 'eip2612-permit-max');
  assert.equal(detections[0]?.metadata?.token, USDC);
  assert.equal(detections[0]?.metadata?.spender, SPENDER);
});

test('wallet-approval-phishing: flags EIP-2612 Permit with max value (decimal string)', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  // 2**256 - 1 as decimal.
  const maxDecimal = '115792089237316195423570985008687907853269984665640564039457584007913129639935';
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X', verifyingContract: USDC },
          primaryType: 'Permit',
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          message: { spender: SPENDER, value: maxDecimal },
        },
      ], 1),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
});

test('wallet-approval-phishing: does NOT flag a Permit with bounded value', async () => {
  const probe = probeById('web3:l1:wallet-approval-phishing');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X', verifyingContract: USDC },
          primaryType: 'Permit',
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          message: { spender: SPENDER, value: '1000' },
        },
      ], 1),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

// ─── 2. deceptive-typed-data-signature ──────────────────────────────────────

test('deceptive-typed-data-signature: flags eth_signTypedData_v1 (legacy format)', async () => {
  const probe = probeById('web3:l1:deceptive-typed-data-signature');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v1', [
        [{ type: 'string', name: 'message', value: 'hello' }],
        '0xowner',
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'legacy-v1-format');
  assert.equal(detections[0]?.severity, 'Medium');
});

test('deceptive-typed-data-signature: flags missing types schema', async () => {
  const probe = probeById('web3:l1:deceptive-typed-data-signature');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        { domain: { name: 'X' }, primaryType: 'Whatever', message: { foo: 1 } },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'missing-types-schema');
  assert.equal(detections[0]?.severity, 'High');
});

test('deceptive-typed-data-signature: flags empty types schema', async () => {
  const probe = probeById('web3:l1:deceptive-typed-data-signature');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        { domain: {}, primaryType: 'Permit', types: {}, message: {} },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'empty-types-schema');
});

test('deceptive-typed-data-signature: flags primaryType not declared in types', async () => {
  const probe = probeById('web3:l1:deceptive-typed-data-signature');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X' },
          primaryType: 'Permit',
          types: { Order: [{ name: 'value', type: 'uint256' }] },
          message: {},
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'primary-type-not-in-types');
  assert.equal(detections[0]?.metadata?.primaryType, 'Permit');
});

test('deceptive-typed-data-signature: does NOT flag a well-formed typed-data payload', async () => {
  const probe = probeById('web3:l1:deceptive-typed-data-signature');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X', verifyingContract: USDC },
          primaryType: 'Permit',
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          message: { value: '1000' },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('deceptive-typed-data-signature: ignores non-signTypedData methods', async () => {
  const probe = probeById('web3:l1:deceptive-typed-data-signature');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_call', [{ to: USDC, data: '0x' }, 'latest'], 0),
      req('personal_sign', ['0x68656c6c6f', '0xowner'], 1),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

// ─── 3. personal-sign-payload-smell ─────────────────────────────────────────

test('personal-sign-payload-smell: flags a 32-byte hash-shaped payload', async () => {
  const probe = probeById('web3:l1:personal-sign-payload-smell');
  const hash = '0x' + 'ab'.repeat(32); // 32 bytes, no readable UTF-8
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [req('personal_sign', [hash, '0xowner'], 5)],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.walletRequestSequence, 5);
  assert.equal(detections[0]?.metadata?.pattern, 'hash-shaped-payload');
});

test('personal-sign-payload-smell: flags an address-bearing UTF-8 payload (hex-encoded)', async () => {
  const probe = probeById('web3:l1:personal-sign-payload-smell');
  // Hex-encode a message containing an EVM address.
  const message = `Please confirm withdrawal to ${SPENDER}`;
  const hex = '0x' + Buffer.from(message, 'utf-8').toString('hex');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [req('personal_sign', [hex, '0xowner'], 2)],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'address-bearing-utf8');
});

test('personal-sign-payload-smell: flags an address-bearing UTF-8 payload (raw string)', async () => {
  const probe = probeById('web3:l1:personal-sign-payload-smell');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('personal_sign', [`Confirm transfer to ${SPENDER}`, '0xowner'], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'address-bearing-utf8');
});

test('personal-sign-payload-smell: does NOT flag a benign sign-in nonce', async () => {
  const probe = probeById('web3:l1:personal-sign-payload-smell');
  const message = 'Sign in to Example dApp\\nNonce: 12345';
  const hex = '0x' + Buffer.from(message, 'utf-8').toString('hex');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [req('personal_sign', [hex, '0xowner'], 0)],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('personal-sign-payload-smell: ignores non-personal_sign methods', async () => {
  const probe = probeById('web3:l1:personal-sign-payload-smell');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [req('eth_signTypedData_v4', ['0xowner', { domain: {}, primaryType: 'X', types: { X: [] }, message: {} }], 0)],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

// ─── 4. eip-7702-set-code-delegation ────────────────────────────────────────

test('eip-7702-set-code-delegation: flags type 0x4 transaction', async () => {
  const probe = probeById('web3:l1:eip-7702-set-code-delegation');
  const delegate = '0xc0de00000000000000000000000000000000beef';
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{
        type: '0x4',
        authorizationList: [{ address: delegate, chainId: '0x1', nonce: '0x0' }],
      }], 11),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.walletRequestSequence, 11);
  assert.equal(detections[0]?.metadata?.pattern, 'eip-7702-set-code');
  assert.equal(detections[0]?.metadata?.delegate, delegate);
});

test('eip-7702-set-code-delegation: flags authorizationList even without explicit type', async () => {
  const probe = probeById('web3:l1:eip-7702-set-code-delegation');
  const delegate = '0xc0de00000000000000000000000000000000beef';
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{
        authorizationList: [{ address: delegate, chainId: '0x1', nonce: '0x0' }],
      }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.delegate, delegate);
});

test('eip-7702-set-code-delegation: emits Critical severity', async () => {
  const probe = probeById('web3:l1:eip-7702-set-code-delegation');
  assert.equal(probe.severity, 'Critical');
});

test('eip-7702-set-code-delegation: does NOT flag a plain transaction', async () => {
  const probe = probeById('web3:l1:eip-7702-set-code-delegation');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: '0x', value: '0x0' }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

// ─── 5. mismatched-chainid-request ──────────────────────────────────────────

test('mismatched-chainid-request: flags wallet_switchEthereumChain to a different chain (ethereum target → base requested)', async () => {
  const probe = probeById('web3:l1:mismatched-chainid-request');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('wallet_switchEthereumChain', [{ chainId: '0x2105' }], 3), // base mainnet
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.walletRequestSequence, 3);
  assert.equal(detections[0]?.metadata?.pattern, 'wallet-chain-switch');
  assert.equal(detections[0]?.metadata?.requestedChainId, '0x2105');
  assert.equal(detections[0]?.metadata?.expectedChainId, '0x1');
});

test('mismatched-chainid-request: does NOT flag wallet_switchEthereumChain to the configured chain', async () => {
  const probe = probeById('web3:l1:mismatched-chainid-request');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('wallet_switchEthereumChain', [{ chainId: '0x1' }], 0),
      req('wallet_switchEthereumChain', [{ chainId: '0x01' }], 1), // leading-zero variant — still matches
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('mismatched-chainid-request: flags typed-data with mismatched domain.chainId', async () => {
  const probe = probeById('web3:l1:mismatched-chainid-request');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X', chainId: 8453 /* base, not the configured ethereum */ },
          primaryType: 'Permit',
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          message: { value: '1' },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'typed-data-chain-mismatch');
  assert.equal(detections[0]?.metadata?.domainChainId, '8453');
  assert.equal(detections[0]?.metadata?.expectedChainId, '1');
});

test('mismatched-chainid-request: domain.chainId as hex string still matches when correct', async () => {
  const probe = probeById('web3:l1:mismatched-chainid-request');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X', chainId: '0x1' },
          primaryType: 'Permit',
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          message: { value: '1' },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('mismatched-chainid-request: ignores typed-data with no domain.chainId at all', async () => {
  const probe = probeById('web3:l1:mismatched-chainid-request');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'X' },
          primaryType: 'Permit',
          types: { Permit: [{ name: 'value', type: 'uint256' }] },
          message: { value: '1' },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

// ─── 6. permit2-mass-approval ───────────────────────────────────────────────

test('permit2-mass-approval: flags Permit2 PermitSingle with max uint160 amount', async () => {
  const probe = probeById('web3:l1:permit2-mass-approval');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2_CONTRACT_ADDRESS },
          primaryType: 'PermitSingle',
          types: { PermitSingle: [] }, // shape minimally valid for the deceptive probe
          message: {
            details: { token: TOKEN, amount: `0x${MAX_UINT160_HEX_LOWER}`, expiration: 9999999999, nonce: 0 },
            spender: SPENDER,
            sigDeadline: 9999999999,
          },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'permit2-amount-max');
  assert.equal(detections[0]?.metadata?.token, TOKEN);
  assert.equal(detections[0]?.metadata?.spender, SPENDER);
});

test('permit2-mass-approval: flags Permit2 PermitBatch with one max entry', async () => {
  const probe = probeById('web3:l1:permit2-mass-approval');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'Permit2', verifyingContract: PERMIT2_CONTRACT_ADDRESS },
          primaryType: 'PermitBatch',
          types: { PermitBatch: [] },
          message: {
            details: [
              { token: TOKEN, amount: '1000', expiration: 1, nonce: 0 },
              { token: USDC, amount: `0x${MAX_UINT160_HEX_LOWER}`, expiration: 9999999999, nonce: 0 },
            ],
            spender: SPENDER,
            sigDeadline: 9999999999,
          },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1, 'one max entry triggers one detection');
  assert.equal(detections[0]?.metadata?.token, USDC);
});

test('permit2-mass-approval: does NOT flag non-Permit2 typed data', async () => {
  const probe = probeById('web3:l1:permit2-mass-approval');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_signTypedData_v4', [
        '0xowner',
        {
          domain: { name: 'NotPermit2', verifyingContract: USDC },
          primaryType: 'Permit',
          types: { Permit: [] },
          message: { details: { amount: `0x${MAX_UINT160_HEX_LOWER}` }, spender: SPENDER },
        },
      ], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});

test('permit2-mass-approval: flags eth_sendTransaction directly to canonical Permit2', async () => {
  const probe = probeById('web3:l1:permit2-mass-approval');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: PERMIT2_CONTRACT_ADDRESS, data: '0x87517c45deadbeef' }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.metadata?.pattern, 'permit2-direct-call');
  // Direct call carries the Medium override (signing alone is High; direct call we
  // cannot know the amount without ABI-decoding Permit2's calldata, so we soften).
  assert.equal(detections[0]?.severity, 'Medium');
});

test('permit2-mass-approval: ignores wallet requests to other contracts', async () => {
  const probe = probeById('web3:l1:permit2-mass-approval');
  const target = createStubTarget({
    chain: 'ethereum',
    walletRequests: [
      req('eth_sendTransaction', [{ to: USDC, data: '0x' }], 0),
    ],
  });
  const detections = await probe.evaluate(target);
  assert.equal(detections.length, 0);
});
