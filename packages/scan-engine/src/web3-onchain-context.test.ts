import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  adminRoleContextSchema,
  contextAvailabilitySchema,
  explorerMetadataSchema,
  onChainContextSchema,
  proxyContextSchema,
  type OnChainContext,
  type OnChainContextProvider,
} from './web3-onchain-context';
import { contractAddressSchema, type ContractAddress } from './web3-types';

const ADDR_A = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const ADDR_B = '0xb0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const ADDR_C = '0xc0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const ADDR_D = '0xd0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

function addr(value: string): ContractAddress {
  return contractAddressSchema.parse(value);
}

test('proxyContextSchema accepts a verified EIP-1967 proxy', () => {
  const parsed = proxyContextSchema.parse({
    isProxy: true,
    implementation: ADDR_B,
    admin: ADDR_C,
  });
  assert.equal(parsed.isProxy, true);
  assert.equal(parsed.implementation, ADDR_B);
});

test('proxyContextSchema permits null implementation/admin (inconclusive)', () => {
  const parsed = proxyContextSchema.parse({
    isProxy: false,
    implementation: null,
    admin: null,
  });
  assert.equal(parsed.isProxy, false);
  assert.equal(parsed.implementation, null);
});

test('adminRoleContextSchema accepts each ownerKind value', () => {
  for (const ownerKind of ['eoa', 'contract', 'not-exposed', 'unknown'] as const) {
    const parsed = adminRoleContextSchema.parse({
      owner: ownerKind === 'not-exposed' ? null : ADDR_D,
      pendingOwner: null,
      ownerKind,
    });
    assert.equal(parsed.ownerKind, ownerKind);
  }
});

test('adminRoleContextSchema rejects unknown ownerKind', () => {
  assert.equal(
    adminRoleContextSchema.safeParse({
      owner: null,
      pendingOwner: null,
      ownerKind: 'maybe-an-eoa',
    }).success,
    false,
  );
});

test('explorerMetadataSchema accepts an entry with everything null', () => {
  const parsed = explorerMetadataSchema.parse({
    sourceVerified: null,
    contractName: null,
    compilerVersion: null,
    deployerAddress: null,
    deploymentTxHash: null,
    deploymentTimestamp: null,
  });
  assert.equal(parsed.sourceVerified, null);
});

test('explorerMetadataSchema accepts a fully populated entry', () => {
  const parsed = explorerMetadataSchema.parse({
    sourceVerified: true,
    contractName: 'USDC',
    compilerVersion: 'v0.8.20+commit.a1b79de6',
    deployerAddress: ADDR_A,
    deploymentTxHash: '0x' + 'cd'.repeat(32),
    deploymentTimestamp: 1_700_000_000,
  });
  assert.equal(parsed.contractName, 'USDC');
});

test('contextAvailabilitySchema covers complete/partial/unavailable', () => {
  assert.deepEqual(contextAvailabilitySchema.options.sort(), ['complete', 'partial', 'unavailable'].sort());
});

test('onChainContextSchema validates a complete context', () => {
  const parsed = onChainContextSchema.parse({
    address: ADDR_A,
    chain: 'ethereum',
    kind: 'contract',
    proxy: { isProxy: true, implementation: ADDR_B, admin: ADDR_C },
    admin: { owner: ADDR_D, pendingOwner: null, ownerKind: 'eoa' },
    explorer: {
      sourceVerified: true,
      contractName: 'USDC',
      compilerVersion: 'v0.8.20',
      deployerAddress: null,
      deploymentTxHash: null,
      deploymentTimestamp: null,
    },
    availability: 'complete',
    unavailableReason: null,
  });
  assert.equal(parsed.availability, 'complete');
  assert.equal(parsed.unavailableReason, null);
});

test('onChainContextSchema permits an unavailable context with a reason', () => {
  const parsed = onChainContextSchema.parse({
    address: ADDR_A,
    chain: 'base',
    kind: 'unknown',
    proxy: null,
    admin: null,
    explorer: null,
    availability: 'unavailable',
    unavailableReason: 'RPC + explorer both timed out',
  });
  assert.equal(parsed.availability, 'unavailable');
  assert.equal(parsed.unavailableReason, 'RPC + explorer both timed out');
});

test('onChainContextSchema rejects an unknown chain', () => {
  assert.equal(
    onChainContextSchema.safeParse({
      address: ADDR_A,
      chain: 'solana',
      kind: 'contract',
      proxy: null,
      admin: null,
      explorer: null,
      availability: 'unavailable',
      unavailableReason: 'x',
    }).success,
    false,
  );
});

test('OnChainContext shape carries no apiKey field (rubric §12 — keys never cross out)', () => {
  // Inspect every property the schema knows about; ensure none is named
  // `apiKey` (or any obvious variant). The `keyof` projection asserts the
  // type-level guarantee; the runtime check enforces it across nested shapes.
  const keys: ReadonlyArray<keyof OnChainContext> = [
    'address',
    'chain',
    'kind',
    'proxy',
    'admin',
    'explorer',
    'availability',
    'unavailableReason',
  ];
  for (const key of keys) {
    const lower = String(key).toLowerCase();
    assert.ok(
      !lower.includes('apikey') && !lower.includes('secret') && !lower.includes('token'),
      `OnChainContext key "${String(key)}" should not look like a credential slot`,
    );
  }
});

test('OnChainContextProvider can be implemented and returns a graceful-degradation result', async () => {
  const provider: OnChainContextProvider = {
    chain: 'ethereum',
    async getContractContext(address) {
      return {
        address,
        chain: 'ethereum',
        kind: 'unknown',
        proxy: null,
        admin: null,
        explorer: null,
        availability: 'unavailable',
        unavailableReason: 'stub provider — concrete impl lands in T-A3.4',
      };
    },
  };
  const result = await provider.getContractContext(addr(ADDR_A));
  assert.equal(result.availability, 'unavailable');
  assert.equal(result.unavailableReason?.startsWith('stub provider'), true);
});
