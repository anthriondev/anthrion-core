import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  chainIdDecimal,
  chainIdHex,
  contractAddressSchema,
  referencedContractSchema,
  walletRequestSchema,
  web3CaptureSchema,
} from './web3-types';

test('contractAddressSchema lower-cases a valid checksummed address', () => {
  const parsed = contractAddressSchema.parse(
    '0xA0b86991c6218B36c1d19D4a2e9eB0cE3606eB48',
  );
  assert.equal(parsed, '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
});

test('contractAddressSchema accepts an already-lower-cased address', () => {
  const parsed = contractAddressSchema.parse(
    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  );
  assert.equal(parsed, '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
});

test('contractAddressSchema rejects malformed input', () => {
  assert.equal(contractAddressSchema.safeParse('').success, false);
  assert.equal(contractAddressSchema.safeParse('0x').success, false);
  // 39 hex digits.
  assert.equal(
    contractAddressSchema.safeParse('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb4').success,
    false,
  );
  // 41 hex digits.
  assert.equal(
    contractAddressSchema.safeParse('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb480').success,
    false,
  );
  // missing 0x prefix.
  assert.equal(
    contractAddressSchema.safeParse('a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48').success,
    false,
  );
  // non-hex character.
  assert.equal(
    contractAddressSchema.safeParse('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb4Z').success,
    false,
  );
  assert.equal(contractAddressSchema.safeParse(42).success, false);
});

test('walletRequestSchema validates a resolved request', () => {
  const parsed = walletRequestSchema.parse({
    sequence: 0,
    method: 'eth_requestAccounts',
    params: [],
    timestamp: 1_700_000_000_000,
    outcome: { kind: 'resolved', result: ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'] },
  });
  assert.equal(parsed.method, 'eth_requestAccounts');
  assert.equal(parsed.outcome.kind, 'resolved');
});

test('walletRequestSchema validates a rejected request with EIP-1193 error shape', () => {
  const parsed = walletRequestSchema.parse({
    sequence: 3,
    method: 'wallet_madeUp',
    params: null,
    timestamp: 1_700_000_001_000,
    outcome: { kind: 'rejected', errorCode: 4200, errorMessage: 'unsupported' },
  });
  if (parsed.outcome.kind !== 'rejected') {
    assert.fail('expected rejected outcome');
  }
  assert.equal(parsed.outcome.errorCode, 4200);
});

test('walletRequestSchema rejects malformed outcome', () => {
  assert.equal(
    walletRequestSchema.safeParse({
      sequence: 0,
      method: 'eth_requestAccounts',
      params: [],
      timestamp: 0,
      outcome: { kind: 'maybe', result: null },
    }).success,
    false,
  );
  assert.equal(
    walletRequestSchema.safeParse({
      sequence: -1,
      method: 'eth_requestAccounts',
      params: [],
      timestamp: 0,
      outcome: { kind: 'resolved', result: null },
    }).success,
    false,
  );
  assert.equal(
    walletRequestSchema.safeParse({
      sequence: 0,
      method: '',
      params: [],
      timestamp: 0,
      outcome: { kind: 'resolved', result: null },
    }).success,
    false,
  );
});

test('referencedContractSchema requires lower-cased address and known origin', () => {
  const parsed = referencedContractSchema.parse({
    address: '0xA0b86991c6218B36c1d19D4a2e9eB0cE3606eB48',
    origin: 'wallet-request',
    walletRequestSequence: 7,
    walletRequestMethod: 'eth_sendTransaction',
  });
  assert.equal(parsed.address, '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
  assert.equal(parsed.origin, 'wallet-request');
  assert.equal(parsed.walletRequestSequence, 7);
});

test('referencedContractSchema rejects unknown origin', () => {
  assert.equal(
    referencedContractSchema.safeParse({
      address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
      origin: 'guess',
    }).success,
    false,
  );
});

test('web3CaptureSchema validates an empty capture', () => {
  const parsed = web3CaptureSchema.parse({
    walletRequests: [],
    referencedContracts: [],
    observedInteractiveFlow: false,
  });
  assert.equal(parsed.observedInteractiveFlow, false);
  assert.equal(parsed.walletRequests.length, 0);
});

test('chainIdHex returns the correct EVM chain id (hex) per chain', () => {
  assert.equal(chainIdHex('ethereum'), '0x1');
  assert.equal(chainIdHex('base'), '0x2105');
});

test('chainIdDecimal returns the correct EVM chain id (decimal) per chain', () => {
  assert.equal(chainIdDecimal('ethereum'), '1');
  assert.equal(chainIdDecimal('base'), '8453');
});
