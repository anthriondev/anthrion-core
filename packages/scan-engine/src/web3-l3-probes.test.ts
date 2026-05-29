import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS,
  STALE_DEPLOYMENT_AGE_SECONDS,
  WELL_KNOWN_TOKEN_REGISTRY,
  elevateOneTierCapHigh,
  maxSeverity,
} from './web3-l3-probe';
import { WEB3_L3_PROBES } from './web3-l3-probes';
import type { OnChainContext } from './web3-onchain-context';
import type { ContractAddress } from './web3-types';
import type { Web3Chain } from './config';

/**
 * Probe-level tests for T-A3.5 (L3 indicators). Runner-level tests
 * (aggregate composition, coverage gaps, outcome state machine) live in
 * `web3-l3.test.ts`.
 *
 * Each probe is exercised against representative `OnChainContext` shapes; the
 * tests assert detection presence/absence, severity calibration, and the
 * "silence when context is incomplete" honesty rule. Slug coverage is also
 * checked — the probe set must match the L3 block of `owaspWeb3CategorySchema`
 * exactly (no missing, no extra).
 */

const ETH_ADDR_A = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as ContractAddress; // canonical USDC on Ethereum
const ETH_ADDR_B = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' as ContractAddress;
const ETH_ADDR_C = '0xcafef00dcafef00dcafef00dcafef00dcafef00d' as ContractAddress;

function ctx(overrides: Partial<OnChainContext> & { address: ContractAddress; chain?: Web3Chain }): OnChainContext {
  return {
    address: overrides.address,
    chain: overrides.chain ?? 'ethereum',
    kind: overrides.kind ?? 'contract',
    proxy: overrides.proxy ?? null,
    admin: overrides.admin ?? null,
    explorer: overrides.explorer ?? null,
    availability: overrides.availability ?? 'complete',
    unavailableReason: overrides.unavailableReason ?? null,
  };
}

function findProbe(id: string) {
  const probe = WEB3_L3_PROBES.find((p) => p.id === id);
  assert.ok(probe !== undefined, `expected probe ${id} in WEB3_L3_PROBES`);
  return probe;
}

// ── Curated probe-set shape ─────────────────────────────────────────────────

test('WEB3_L3_PROBES covers exactly the five L3 indicator slugs', async () => {
  const slugs = WEB3_L3_PROBES.map((p) => p.category).sort();
  assert.deepEqual(slugs, [
    'contract-source-not-verified',
    'eoa-admin-single-key',
    'proxy-without-verified-implementation',
    'recent-contract-deployment',
    'token-impersonation-indicator',
  ]);
  // ids all carry the `web3:l3:` prefix.
  for (const probe of WEB3_L3_PROBES) {
    assert.match(probe.id, /^web3:l3:/, `probe ${probe.id} must use web3:l3: prefix`);
  }
});

test('WEB3_L3_PROBES is frozen — curated set is immutable', () => {
  assert.equal(Object.isFrozen(WEB3_L3_PROBES), true);
});

// ── Helper: elevateOneTierCapHigh ───────────────────────────────────────────

test('elevateOneTierCapHigh elevates one tier and caps at High', () => {
  assert.equal(elevateOneTierCapHigh('Info'), 'Low');
  assert.equal(elevateOneTierCapHigh('Low'), 'Medium');
  assert.equal(elevateOneTierCapHigh('Medium'), 'High');
  // Cap at High — elevating High does NOT synthesise Critical.
  assert.equal(elevateOneTierCapHigh('High'), 'High');
  // Defensive: Critical input is capped DOWN to High (never propagated up).
  assert.equal(elevateOneTierCapHigh('Critical'), 'High');
});

test('maxSeverity returns the more-severe input', () => {
  assert.equal(maxSeverity('Low', 'High'), 'High');
  assert.equal(maxSeverity('Critical', 'High'), 'Critical');
  assert.equal(maxSeverity('Medium', 'Medium'), 'Medium');
  assert.equal(maxSeverity('Info', 'Low'), 'Low');
});

// ── contract-source-not-verified ────────────────────────────────────────────

test('contract-source-not-verified: silent when explorer record absent', async () => {
  const probe = findProbe('web3:l3:contract-source-not-verified');
  const detections = await probe.evaluate(ctx({ address: ETH_ADDR_B, explorer: null }));
  assert.equal(detections.length, 0);
});

test('contract-source-not-verified: silent when source IS verified', async () => {
  const probe = findProbe('web3:l3:contract-source-not-verified');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: 'GoodContract',
        compilerVersion: '0.8.20',
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('contract-source-not-verified: Medium for fresh/unknown-age unverified contract', async () => {
  const probe = findProbe('web3:l3:contract-source-not-verified');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: false,
        contractName: null,
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null, // unknown age → treat as fresh (more cautious)
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity, 'Medium');
  assert.match(detections[0]?.rationale ?? '', /sourceVerified=false/);
  assert.equal(detections[0]?.metadata?.ageBucket, 'fresh-or-unknown');
});

test('contract-source-not-verified: Low for old (>180d) unverified contract', async () => {
  const probe = findProbe('web3:l3:contract-source-not-verified');
  const oldTimestamp = Math.floor(Date.now() / 1000) - STALE_DEPLOYMENT_AGE_SECONDS - 86_400;
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: false,
        contractName: null,
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: oldTimestamp,
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity, 'Low');
  assert.equal(detections[0]?.metadata?.ageBucket, 'aged');
});

// ── proxy-without-verified-implementation ───────────────────────────────────

test('proxy-without-verified-implementation: silent when not a proxy', async () => {
  const probe = findProbe('web3:l3:proxy-without-verified-implementation');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      proxy: { isProxy: false, implementation: null, admin: null },
    }),
  );
  assert.equal(detections.length, 0);
});

test('proxy-without-verified-implementation: silent when proxy implementation IS resolved', async () => {
  const probe = findProbe('web3:l3:proxy-without-verified-implementation');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      proxy: {
        isProxy: true,
        implementation: '0x1111111111111111111111111111111111111111' as ContractAddress,
        admin: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('proxy-without-verified-implementation: Medium when proxy implementation unresolved', async () => {
  const probe = findProbe('web3:l3:proxy-without-verified-implementation');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      proxy: {
        isProxy: true,
        implementation: null,
        admin: '0x2222222222222222222222222222222222222222' as ContractAddress,
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity ?? probe.severity, 'Medium');
  assert.equal(detections[0]?.metadata?.proxyResolution, 'implementation-unresolved');
});

// ── eoa-admin-single-key ────────────────────────────────────────────────────

test('eoa-admin-single-key: silent when admin context absent', async () => {
  const probe = findProbe('web3:l3:eoa-admin-single-key');
  const detections = await probe.evaluate(ctx({ address: ETH_ADDR_B, admin: null }));
  assert.equal(detections.length, 0);
});

test('eoa-admin-single-key: silent when owner is a contract (multisig / timelock pattern)', async () => {
  const probe = findProbe('web3:l3:eoa-admin-single-key');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      admin: {
        owner: '0x3333333333333333333333333333333333333333' as ContractAddress,
        pendingOwner: null,
        ownerKind: 'contract',
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('eoa-admin-single-key: silent when owner() is not exposed', async () => {
  const probe = findProbe('web3:l3:eoa-admin-single-key');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      admin: { owner: null, pendingOwner: null, ownerKind: 'not-exposed' },
    }),
  );
  assert.equal(detections.length, 0);
});

test('eoa-admin-single-key: Medium when EOA admin with verified source', async () => {
  const probe = findProbe('web3:l3:eoa-admin-single-key');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      admin: {
        owner: '0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed' as ContractAddress,
        pendingOwner: null,
        ownerKind: 'eoa',
      },
      explorer: {
        sourceVerified: true,
        contractName: 'Verified',
        compilerVersion: '0.8.20',
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity, 'Medium');
  assert.equal(detections[0]?.metadata?.combinedWithUnverifiedSource, undefined);
});

test('eoa-admin-single-key: High when EOA admin COMBINED with unverified source', async () => {
  const probe = findProbe('web3:l3:eoa-admin-single-key');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      admin: {
        owner: '0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed' as ContractAddress,
        pendingOwner: null,
        ownerKind: 'eoa',
      },
      explorer: {
        sourceVerified: false,
        contractName: null,
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity, 'High');
  assert.equal(detections[0]?.metadata?.combinedWithUnverifiedSource, 'true');
  assert.match(detections[0]?.rationale ?? '', /combined indicator/);
});

// ── recent-contract-deployment ──────────────────────────────────────────────

test('recent-contract-deployment: silent when explorer record absent', async () => {
  const probe = findProbe('web3:l3:recent-contract-deployment');
  const detections = await probe.evaluate(ctx({ address: ETH_ADDR_B, explorer: null }));
  assert.equal(detections.length, 0);
});

test('recent-contract-deployment: silent when deploymentTimestamp is null', async () => {
  const probe = findProbe('web3:l3:recent-contract-deployment');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: 'Old',
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('recent-contract-deployment: silent when deployment is older than 72h', async () => {
  const probe = findProbe('web3:l3:recent-contract-deployment');
  const oldTimestamp =
    Math.floor(Date.now() / 1000) - DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS - 3600;
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: 'Old',
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: oldTimestamp,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('recent-contract-deployment: silent on future-dated deployment (clock skew)', async () => {
  const probe = findProbe('web3:l3:recent-contract-deployment');
  const futureTimestamp = Math.floor(Date.now() / 1000) + 3600;
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: 'Future',
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: futureTimestamp,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('recent-contract-deployment: Medium for contract deployed in the last 72h', async () => {
  const probe = findProbe('web3:l3:recent-contract-deployment');
  const recentTimestamp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: 'Fresh',
        compilerVersion: '0.8.20',
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: recentTimestamp,
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity ?? probe.severity, 'Medium');
  assert.match(detections[0]?.evidence ?? '', /~1h ago/);
});

// ── token-impersonation-indicator ───────────────────────────────────────────

test('token-impersonation-indicator: silent when explorer record absent', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  const detections = await probe.evaluate(ctx({ address: ETH_ADDR_B, explorer: null }));
  assert.equal(detections.length, 0);
});

test('token-impersonation-indicator: silent when contractName is null', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: null,
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('token-impersonation-indicator: silent on the canonical USDC contract', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_A, // canonical USDC
      explorer: {
        sourceVerified: true,
        contractName: 'USDC',
        compilerVersion: '0.8.20',
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('token-impersonation-indicator: silent on non-canonical name (USDC-bridged etc.)', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      explorer: {
        sourceVerified: true,
        contractName: 'USDC-bridged',
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});

test('token-impersonation-indicator: High when name matches canonical token at different address', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B, // NOT the canonical USDC address
      explorer: {
        sourceVerified: true,
        contractName: 'USDC',
        compilerVersion: '0.8.20',
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 1);
  assert.equal(detections[0]?.severity ?? probe.severity, 'High');
  assert.equal(detections[0]?.metadata?.canonicalToken, 'USDC');
  assert.equal(
    detections[0]?.metadata?.canonicalAddress,
    WELL_KNOWN_TOKEN_REGISTRY.find((t) => t.name === 'USDC')?.byChain.ethereum,
  );
});

test('token-impersonation-indicator: case-insensitive name match', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_C,
      explorer: {
        sourceVerified: true,
        contractName: 'usdc', // lowercase
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 1);
});

test('token-impersonation-indicator: silent when matched token is not registered on the scan chain', async () => {
  const probe = findProbe('web3:l3:token-impersonation-indicator');
  // USDT does NOT have a Base entry in the registry; a contract named USDT on
  // Base should be silent (we can't accuse it of impersonation when we have
  // no canonical to compare against).
  const detections = await probe.evaluate(
    ctx({
      address: ETH_ADDR_B,
      chain: 'base',
      explorer: {
        sourceVerified: true,
        contractName: 'USDT',
        compilerVersion: null,
        deployerAddress: null,
        deploymentTxHash: null,
        deploymentTimestamp: null,
      },
    }),
  );
  assert.equal(detections.length, 0);
});
