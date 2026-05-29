import assert from 'node:assert/strict';
import { test } from 'node:test';

import { WEB3_L2_PROBES } from './web3-l2-probes';
import {
  KNOWN_BAD_DOMAIN_LIST,
  isCrossOriginResource,
  l2SriEligible,
  safeParseUrl,
  type Web3L2Probe,
} from './web3-l2-probe';
import type { ObservedCookie, PageResource, TlsSecurityDetails } from './web-probe';
import type { Web3DAppTarget } from './web3-target';
import type { Web3Chain } from './config';

/**
 * Probe-level tests for T-A3.6 (L2 indicators). Runner-level tests
 * (outcome state machine, coverage notes aggregation, timeouts) live in
 * `web3-l2.test.ts`.
 */

interface StubTargetInput {
  chain?: Web3Chain;
  finalUrl: string;
  isHttps?: boolean;
  resources?: readonly PageResource[];
  securityDetails?: TlsSecurityDetails | null;
}

function stubTarget(input: StubTargetInput): Web3DAppTarget {
  return {
    chain: input.chain ?? 'ethereum',
    requestedUrl: input.finalUrl,
    finalUrl: input.finalUrl,
    status: 200,
    responseHeaders: {},
    isHttps: input.isHttps ?? input.finalUrl.startsWith('https:'),
    cookies: () => Promise.resolve([] as readonly ObservedCookie[]),
    securityDetails: () => Promise.resolve(input.securityDetails ?? null),
    html: () => Promise.resolve(''),
    resources: () => Promise.resolve(input.resources ?? []),
    walletRequests: () => Promise.resolve([]),
    referencedContracts: () => Promise.resolve([]),
    observedInteractiveFlow: () => Promise.resolve(false),
  };
}

function findProbe(id: string): Web3L2Probe {
  const probe = WEB3_L2_PROBES.find((p) => p.id === id);
  assert.ok(probe !== undefined, `expected probe ${id} in WEB3_L2_PROBES`);
  return probe;
}

function resource(overrides: Partial<PageResource> & { url: string; tag: PageResource['tag'] }): PageResource {
  return {
    tag: overrides.tag,
    url: overrides.url,
    rel: overrides.rel ?? null,
    integrity: overrides.integrity ?? null,
    crossorigin: overrides.crossorigin ?? null,
  };
}

// ── Curated probe-set shape ─────────────────────────────────────────────────

test('WEB3_L2_PROBES covers exactly the three L2 slugs', () => {
  const slugs = WEB3_L2_PROBES.map((p) => p.category).sort();
  assert.deepEqual(slugs, [
    'dapp-dns-or-tls-hygiene',
    'dapp-frontend-integrity',
    'known-bad-domain-reference',
  ]);
  for (const probe of WEB3_L2_PROBES) {
    assert.match(probe.id, /^web3:l2:/, `probe ${probe.id} must use web3:l2: prefix`);
  }
});

test('WEB3_L2_PROBES is frozen — curated set is immutable', () => {
  assert.equal(Object.isFrozen(WEB3_L2_PROBES), true);
});

// ── Shared helpers ──────────────────────────────────────────────────────────

test('l2SriEligible: scripts always eligible, link only when rel=stylesheet', () => {
  assert.equal(l2SriEligible('script', null), true);
  assert.equal(l2SriEligible('link', 'stylesheet'), true);
  assert.equal(l2SriEligible('link', 'preconnect'), false);
  assert.equal(l2SriEligible('link', null), false);
  assert.equal(l2SriEligible('img', null), false);
  assert.equal(l2SriEligible('iframe', null), false);
});

test('safeParseUrl: rejects relative, data:, javascript:', () => {
  assert.ok(safeParseUrl('https://example.com/x.js') !== undefined);
  assert.ok(safeParseUrl('http://example.com/x.js') !== undefined);
  assert.equal(safeParseUrl('/relative/x.js'), undefined);
  assert.equal(safeParseUrl('data:text/plain,hello'), undefined);
  assert.equal(safeParseUrl('javascript:alert(1)'), undefined);
  assert.equal(safeParseUrl(''), undefined);
});

test('isCrossOriginResource: only when origin differs', () => {
  const page = new URL('https://dapp.example.com/index.html');
  assert.equal(isCrossOriginResource(new URL('https://dapp.example.com/x.js'), page), false);
  assert.equal(isCrossOriginResource(new URL('https://cdn.example.com/x.js'), page), true);
  assert.equal(isCrossOriginResource(new URL('http://dapp.example.com/x.js'), page), true); // proto differs
});

// ── dapp-frontend-integrity ─────────────────────────────────────────────────

test('frontend-integrity: silent on same-origin scripts even without SRI', async () => {
  const probe = findProbe('web3:l2:dapp-frontend-integrity');
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://dapp.example/',
      resources: [resource({ tag: 'script', url: 'https://dapp.example/app.js' })],
    }),
  );
  assert.equal(result.detections.length, 0);
});

test('frontend-integrity: emits Medium per cross-origin script missing integrity', async () => {
  const probe = findProbe('web3:l2:dapp-frontend-integrity');
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://dapp.example/',
      resources: [
        resource({ tag: 'script', url: 'https://cdn1.invalid/a.js' }),
        resource({ tag: 'script', url: 'https://cdn2.invalid/b.js' }),
        resource({ tag: 'link', rel: 'stylesheet', url: 'https://cdn3.invalid/c.css' }),
      ],
    }),
  );
  // 3 cross-origin SRI-eligible without integrity → 3 detections.
  assert.equal(result.detections.length, 3);
  for (const d of result.detections) {
    assert.equal(d.severity, 'Medium');
    assert.equal(d.metadata?.subcheck, 'sri-absence');
  }
});

test('frontend-integrity: silent when cross-origin script HAS integrity', async () => {
  const probe = findProbe('web3:l2:dapp-frontend-integrity');
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://dapp.example/',
      resources: [
        resource({
          tag: 'script',
          url: 'https://cdn.invalid/a.js',
          integrity: 'sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          crossorigin: 'anonymous',
        }),
      ],
    }),
  );
  assert.equal(result.detections.length, 0);
});

test('frontend-integrity: silent when resources list is empty (no false positive)', async () => {
  const probe = findProbe('web3:l2:dapp-frontend-integrity');
  const result = await probe.evaluate(
    stubTarget({ finalUrl: 'https://dapp.example/', resources: [] }),
  );
  assert.equal(result.detections.length, 0);
  assert.equal(result.coverageNotes?.length ?? 0, 0);
});

// ── known-bad-domain-reference ──────────────────────────────────────────────

test('known-bad-domain: silent when no resources match the blocklist', async () => {
  const probe = findProbe('web3:l2:known-bad-domain-reference');
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://dapp.example/',
      resources: [
        resource({ tag: 'script', url: 'https://safe-cdn.invalid/x.js' }),
        resource({ tag: 'link', rel: 'stylesheet', url: 'https://other.invalid/y.css' }),
      ],
    }),
  );
  assert.equal(result.detections.length, 0);
});

test('known-bad-domain: emits High per matched resource hostname', async () => {
  const probe = findProbe('web3:l2:known-bad-domain-reference');
  const badHost = KNOWN_BAD_DOMAIN_LIST[0];
  assert.ok(badHost !== undefined);
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://dapp.example/',
      resources: [
        resource({ tag: 'script', url: `https://${badHost}/drainer.js` }),
        resource({ tag: 'script', url: `https://${badHost.toUpperCase()}/other.js` }),
      ],
    }),
  );
  // Exact hostname (case-insensitive via lowercase): 2 detections.
  assert.equal(result.detections.length, 2);
  for (const d of result.detections) {
    assert.equal(d.metadata?.hostname, badHost.toLowerCase());
  }
});

test('known-bad-domain: detects when the page URL itself is on the blocklist', async () => {
  const probe = findProbe('web3:l2:known-bad-domain-reference');
  const badHost = KNOWN_BAD_DOMAIN_LIST[0];
  assert.ok(badHost !== undefined);
  const result = await probe.evaluate(
    stubTarget({ finalUrl: `https://${badHost}/`, resources: [] }),
  );
  assert.equal(result.detections.length, 1);
  assert.equal(result.detections[0]?.metadata?.source, 'page-url');
});

test('known-bad-domain: does NOT substring-match (safe-X.com vs X.com)', async () => {
  const probe = findProbe('web3:l2:known-bad-domain-reference');
  const badHost = KNOWN_BAD_DOMAIN_LIST[0];
  assert.ok(badHost !== undefined);
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://dapp.example/',
      resources: [
        resource({ tag: 'script', url: `https://safe-${badHost}/x.js` }), // substring extension
        resource({ tag: 'script', url: `https://${badHost}.com.fakeworld.invalid/x.js` }), // suffix
      ],
    }),
  );
  assert.equal(result.detections.length, 0);
});

// ── dapp-dns-or-tls-hygiene ─────────────────────────────────────────────────

test('dns-or-tls: HTTPS page without TLS details → coverage note, not a finding', async () => {
  const probe = findProbe('web3:l2:dapp-dns-or-tls-hygiene');
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://example.invalid/',
      isHttps: true,
      securityDetails: null,
    }),
  );
  // Detections may exist for DNS (resolveNs will likely fail on .invalid); we
  // only assert the TLS-side coverage note presence here.
  const kinds = (result.coverageNotes ?? []).map((n) => n.kind);
  assert.ok(kinds.includes('web3-l2-tls-details-unavailable'));
});

test('dns-or-tls: HTTP page → tls-not-applicable coverage note', async () => {
  const probe = findProbe('web3:l2:dapp-dns-or-tls-hygiene');
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'http://example.invalid/',
      isHttps: false,
    }),
  );
  const kinds = (result.coverageNotes ?? []).map((n) => n.kind);
  assert.ok(kinds.includes('web3-l2-tls-not-applicable'));
});

test('dns-or-tls: cert near-expiry (≤ 14 days) → Medium detection', async () => {
  const probe = findProbe('web3:l2:dapp-dns-or-tls-hygiene');
  const nowSec = Math.floor(Date.now() / 1000);
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://example.invalid/',
      isHttps: true,
      securityDetails: {
        protocol: 'TLS 1.3',
        issuer: 'Test CA',
        subjectName: 'example.invalid',
        validFrom: nowSec - 365 * 86_400,
        validTo: nowSec + 5 * 86_400, // 5 days left
      },
    }),
  );
  const nearExpiry = result.detections.find((d) => d.metadata?.subcheck === 'tls-cert-near-expiry');
  assert.ok(nearExpiry !== undefined);
  assert.equal(nearExpiry.metadata?.daysLeft, '5');
});

test('dns-or-tls: very-fresh cert (≤ 7 days old) → Medium detection', async () => {
  const probe = findProbe('web3:l2:dapp-dns-or-tls-hygiene');
  const nowSec = Math.floor(Date.now() / 1000);
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://example.invalid/',
      isHttps: true,
      securityDetails: {
        protocol: 'TLS 1.3',
        issuer: 'Test CA',
        subjectName: 'example.invalid',
        validFrom: nowSec - 2 * 86_400, // 2 days old
        validTo: nowSec + 365 * 86_400,
      },
    }),
  );
  const veryFresh = result.detections.find((d) => d.metadata?.subcheck === 'tls-cert-very-fresh');
  assert.ok(veryFresh !== undefined);
  assert.equal(veryFresh.metadata?.daysOld, '2');
});

test('dns-or-tls: cert healthy and old → no TLS detection (only honest skip note)', async () => {
  const probe = findProbe('web3:l2:dapp-dns-or-tls-hygiene');
  const nowSec = Math.floor(Date.now() / 1000);
  const result = await probe.evaluate(
    stubTarget({
      finalUrl: 'https://example.invalid/',
      isHttps: true,
      securityDetails: {
        protocol: 'TLS 1.3',
        issuer: 'Test CA',
        subjectName: 'example.invalid',
        validFrom: nowSec - 90 * 86_400, // 90 days old
        validTo: nowSec + 90 * 86_400, // 90 days left
      },
    }),
  );
  assert.equal(
    result.detections.filter((d) => String(d.metadata?.subcheck ?? '').startsWith('tls-')).length,
    0,
  );
});

test('dns-or-tls: always emits the DNSSEC-skipped coverage note (hand-rolled scope)', async () => {
  const probe = findProbe('web3:l2:dapp-dns-or-tls-hygiene');
  const result = await probe.evaluate(
    stubTarget({ finalUrl: 'https://example.invalid/', isHttps: true, securityDetails: {} }),
  );
  const kinds = (result.coverageNotes ?? []).map((n) => n.kind);
  assert.ok(kinds.includes('web3-l2-dnssec-skipped'));
});
