import assert from 'node:assert/strict';
import { test } from 'node:test';

import { harvestReferencedContracts } from './web3-address-harvest';
import type { WalletRequest } from './web3-types';

const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const USDC_CHECKSUM = '0xA0b86991c6218B36c1d19D4a2e9eB0cE3606eB48';
const UNISWAP_V3_ROUTER = '0xe592427a0aece92de3edee1f18e0157c05861564';
const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const RANDOM_CONTRACT = '0xabababababababababababababababababababab';

function ethSendTransactionRequest(seq: number, to: string): WalletRequest {
  return {
    sequence: seq,
    method: 'eth_sendTransaction',
    params: [{ from: '0xfromfromfromfromfromfromfromfromfromfrom', to, data: '0x' }],
    timestamp: 0,
    outcome: { kind: 'resolved', result: '0xbb' },
  };
}

test('extracts `to` from eth_sendTransaction', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [ethSendTransactionRequest(0, USDC_CHECKSUM)],
    html: '',
  });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, USDC);
  assert.equal(harvest[0]?.origin, 'wallet-request');
  assert.equal(harvest[0]?.walletRequestMethod, 'eth_sendTransaction');
  assert.equal(harvest[0]?.walletRequestSequence, 0);
});

test('extracts `to` from eth_call and eth_estimateGas', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [
      {
        sequence: 0,
        method: 'eth_call',
        params: [{ to: UNISWAP_V3_ROUTER, data: '0x' }, 'latest'],
        timestamp: 0,
        outcome: { kind: 'resolved', result: '0x' },
      },
      {
        sequence: 1,
        method: 'eth_estimateGas',
        params: [{ to: PERMIT2, data: '0x' }],
        timestamp: 0,
        outcome: { kind: 'resolved', result: '0x5208' },
      },
    ],
    html: '',
  });
  const addresses = harvest.map((c) => c.address).sort();
  assert.deepEqual(addresses, [PERMIT2, UNISWAP_V3_ROUTER].sort());
});

test('extracts verifyingContract from eth_signTypedData_v4 domain', () => {
  const typedData = {
    types: { EIP712Domain: [], Permit: [] },
    primaryType: 'Permit',
    domain: { name: 'USDC', verifyingContract: USDC_CHECKSUM, chainId: 1 },
    message: {},
  };
  const harvest = harvestReferencedContracts({
    walletRequests: [
      {
        sequence: 0,
        method: 'eth_signTypedData_v4',
        params: ['0xabc', typedData],
        timestamp: 0,
        outcome: { kind: 'resolved', result: '0x00' },
      },
    ],
    html: '',
  });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, USDC);
});

test('extracts verifyingContract from typed data passed as JSON string', () => {
  const typedData = JSON.stringify({
    domain: { verifyingContract: PERMIT2 },
    message: {},
    primaryType: 'X',
    types: {},
  });
  const harvest = harvestReferencedContracts({
    walletRequests: [
      {
        sequence: 0,
        method: 'eth_signTypedData_v4',
        params: ['0xabc', typedData],
        timestamp: 0,
        outcome: { kind: 'resolved', result: '0x00' },
      },
    ],
    html: '',
  });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, PERMIT2);
});

test('extracts options.address from wallet_watchAsset', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [
      {
        sequence: 0,
        method: 'wallet_watchAsset',
        params: {
          type: 'ERC20',
          options: { address: USDC, symbol: 'USDC', decimals: 6 },
        },
        timestamp: 0,
        outcome: { kind: 'resolved', result: true },
      },
    ],
    html: '',
  });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, USDC);
});

test('iterates calls[] from wallet_sendCalls (EIP-5792 batch)', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [
      {
        sequence: 0,
        method: 'wallet_sendCalls',
        params: [
          {
            version: '1.0',
            chainId: '0x1',
            calls: [
              { to: USDC, data: '0x' },
              { to: UNISWAP_V3_ROUTER, data: '0x' },
            ],
          },
        ],
        timestamp: 0,
        outcome: { kind: 'resolved', result: { id: '0xbb' } },
      },
    ],
    html: '',
  });
  const addrs = harvest.map((c) => c.address).sort();
  assert.deepEqual(addrs, [USDC, UNISWAP_V3_ROUTER].sort());
});

test('harvests EVM addresses from the rendered HTML as dom-reference', () => {
  const html = `<a href="https://etherscan.io/address/${RANDOM_CONTRACT}">contract</a>`;
  const harvest = harvestReferencedContracts({ walletRequests: [], html });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, RANDOM_CONTRACT);
  assert.equal(harvest[0]?.origin, 'dom-reference');
  assert.equal(harvest[0]?.walletRequestMethod, undefined);
  assert.equal(harvest[0]?.walletRequestSequence, undefined);
});

test('drops the zero address from both wallet requests and DOM', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [ethSendTransactionRequest(0, ZERO_ADDRESS)],
    html: `<p>${ZERO_ADDRESS}</p>`,
  });
  assert.equal(harvest.length, 0);
});

test('dedupes the same address across sources, preferring wallet-request', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [ethSendTransactionRequest(2, USDC_CHECKSUM)],
    html: `<p>${USDC_CHECKSUM}</p>`,
  });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, USDC);
  assert.equal(harvest[0]?.origin, 'wallet-request');
  assert.equal(harvest[0]?.walletRequestSequence, 2);
});

test('dedupes by lower-cased address regardless of source casing', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [],
    html: `<p>${USDC_CHECKSUM}</p><p>${USDC}</p>`,
  });
  assert.equal(harvest.length, 1);
  assert.equal(harvest[0]?.address, USDC);
});

test('ignores malformed wallet request params without crashing', () => {
  const harvest = harvestReferencedContracts({
    walletRequests: [
      {
        sequence: 0,
        method: 'eth_sendTransaction',
        params: null,
        timestamp: 0,
        outcome: { kind: 'rejected', errorCode: -32602, errorMessage: 'bad' },
      },
      {
        sequence: 1,
        method: 'eth_signTypedData_v4',
        params: ['0xabc', 'not valid json'],
        timestamp: 0,
        outcome: { kind: 'rejected', errorCode: -32603, errorMessage: 'bad' },
      },
      {
        sequence: 2,
        method: 'eth_call',
        params: [{ to: 12345 }, 'latest'],
        timestamp: 0,
        outcome: { kind: 'resolved', result: '0x' },
      },
    ],
    html: '',
  });
  assert.equal(harvest.length, 0);
});

test('drops 40-hex-character matches that are part of a longer hex blob', () => {
  // A 64-hex-char blob — should NOT yield a 40-char address match (word boundary).
  const longBlob = '0x' + 'ab'.repeat(32);
  const harvest = harvestReferencedContracts({ walletRequests: [], html: longBlob });
  assert.equal(harvest.length, 0);
});
