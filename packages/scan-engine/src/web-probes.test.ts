import assert from 'node:assert/strict';
import { test } from 'node:test';

import { findingSchema } from './finding';
import type {
  ObservedCookie,
  PageContext,
  PageResource,
  TlsSecurityDetails,
  WebProbe,
} from './web-probe';
import { WEB_PROBES } from './web-probes';

/**
 * Probe logic tests (T2.6 Part B) using an in-memory `PageContext` fake — fast,
 * no browser. The real Playwright path is proven separately in `web-scan.test.ts`
 * (real Chromium + a local HTTP server). Together: probe logic is unit-tested AND
 * the end-to-end browser path is exercised against a live server (not a full mock).
 */

interface FakeCtxInit {
  finalUrl?: string;
  status?: number;
  headers?: Record<string, string>;
  cookies?: ObservedCookie[];
  securityDetails?: TlsSecurityDetails | null;
  html?: string;
  resources?: PageResource[];
}

function fakeCtx(init: FakeCtxInit = {}): PageContext {
  const finalUrl = init.finalUrl ?? 'https://app.example/';
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(init.headers ?? {})) {
    headers[key.toLowerCase()] = value;
  }
  return {
    requestedUrl: finalUrl,
    finalUrl,
    status: init.status ?? 200,
    responseHeaders: headers,
    isHttps: finalUrl.startsWith('https:'),
    cookies: () => Promise.resolve(init.cookies ?? []),
    securityDetails: () => Promise.resolve(init.securityDetails ?? null),
    html: () => Promise.resolve(init.html ?? '<!doctype html><html><body>ok</body></html>'),
    resources: () => Promise.resolve(init.resources ?? []),
  };
}

function cookie(over: Partial<ObservedCookie> = {}): ObservedCookie {
  return {
    name: 'sid',
    domain: 'app.example',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
    ...over,
  };
}

function resource(over: Partial<PageResource> = {}): PageResource {
  return { tag: 'script', url: 'https://app.example/app.js', rel: null, integrity: null, crossorigin: null, ...over };
}

function probeById(id: string): WebProbe {
  const probe = WEB_PROBES.find((p) => p.id === id);
  if (probe === undefined) {
    throw new Error(`probe not found: ${id}`);
  }
  return probe;
}

/** Fully-hardened HTTPS page headers (used as the "secure" baseline). */
const SECURE_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};

// --- A02: Security Misconfiguration ---------------------------------------

test('missing-csp: detected when no header and no meta; clean when header present; clean via meta', async () => {
  const probe = probeById('misconfig-missing-csp');

  const missing = await probe.evaluate(fakeCtx({ headers: {} }));
  assert.equal(missing.detected, true);
  assert.ok(missing.evidence);

  const viaHeader = await probe.evaluate(fakeCtx({ headers: { 'content-security-policy': "default-src 'self'" } }));
  assert.equal(viaHeader.detected, false);

  const viaMeta = await probe.evaluate(
    fakeCtx({ html: '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>' }),
  );
  assert.equal(viaMeta.detected, false);
});

test('missing-x-content-type-options: detected when absent or wrong; clean on nosniff', async () => {
  const probe = probeById('misconfig-missing-x-content-type-options');
  assert.equal((await probe.evaluate(fakeCtx({ headers: {} }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ headers: { 'x-content-type-options': 'foo' } }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ headers: { 'x-content-type-options': 'nosniff' } }))).detected, false);
});

test('missing-x-frame-options: clean via XFO or CSP frame-ancestors; detected when neither', async () => {
  const probe = probeById('misconfig-missing-x-frame-options');
  assert.equal((await probe.evaluate(fakeCtx({ headers: { 'x-frame-options': 'DENY' } }))).detected, false);
  assert.equal(
    (await probe.evaluate(fakeCtx({ headers: { 'content-security-policy': "frame-ancestors 'none'" } }))).detected,
    false,
  );
  assert.equal((await probe.evaluate(fakeCtx({ headers: {} }))).detected, true);
});

test('missing-referrer-policy: detected when absent; clean when present', async () => {
  const probe = probeById('misconfig-missing-referrer-policy');
  assert.equal((await probe.evaluate(fakeCtx({ headers: {} }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ headers: { 'referrer-policy': 'no-referrer' } }))).detected, false);
});

test('permissive-cors: clean when absent/specific; Medium for *; High for * + credentials', async () => {
  const probe = probeById('misconfig-permissive-cors');
  assert.equal((await probe.evaluate(fakeCtx({ headers: {} }))).detected, false);
  assert.equal(
    (await probe.evaluate(fakeCtx({ headers: { 'access-control-allow-origin': 'https://trusted.example' } }))).detected,
    false,
  );

  const wildcard = await probe.evaluate(fakeCtx({ headers: { 'access-control-allow-origin': '*' } }));
  assert.equal(wildcard.detected, true);
  assert.equal(wildcard.severity, undefined); // falls back to probe.severity (Medium)

  const withCreds = await probe.evaluate(
    fakeCtx({ headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' } }),
  );
  assert.equal(withCreds.detected, true);
  assert.equal(withCreds.severity, 'High');
});

test('software-disclosure: detected for x-powered-by / versioned Server; clean for bare Server', async () => {
  const probe = probeById('misconfig-software-disclosure');
  assert.equal((await probe.evaluate(fakeCtx({ headers: { 'x-powered-by': 'PHP/8.2.1' } }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ headers: { server: 'Apache/2.4.41 (Ubuntu)' } }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ headers: { server: 'cloudflare' } }))).detected, false);
  assert.equal((await probe.evaluate(fakeCtx({ headers: {} }))).detected, false);
});

test('cookie-missing-httponly: detected when a cookie lacks HttpOnly; clean otherwise / no cookies', async () => {
  const probe = probeById('misconfig-cookie-missing-httponly');
  assert.equal((await probe.evaluate(fakeCtx({ cookies: [] }))).detected, false);
  assert.equal((await probe.evaluate(fakeCtx({ cookies: [cookie({ httpOnly: true })] }))).detected, false);
  const bad = await probe.evaluate(fakeCtx({ cookies: [cookie({ name: 'token', httpOnly: false })] }));
  assert.equal(bad.detected, true);
  assert.match(bad.evidence ?? '', /token/);
});

test('cookie-samesite-none-insecure: detected for SameSite=None without Secure', async () => {
  const probe = probeById('misconfig-cookie-samesite-none-insecure');
  assert.equal((await probe.evaluate(fakeCtx({ cookies: [cookie({ sameSite: 'None', secure: true })] }))).detected, false);
  assert.equal((await probe.evaluate(fakeCtx({ cookies: [cookie({ sameSite: 'Lax', secure: false })] }))).detected, false);
  assert.equal(
    (await probe.evaluate(fakeCtx({ cookies: [cookie({ name: 'x', sameSite: 'None', secure: false })] }))).detected,
    true,
  );
});

// --- A04: Cryptographic Failures ------------------------------------------

test('no-https: detected on http; clean on https', async () => {
  const probe = probeById('crypto-no-https');
  assert.equal((await probe.evaluate(fakeCtx({ finalUrl: 'http://app.example/' }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/' }))).detected, false);
});

test('missing-hsts: detected on https without HSTS; n/a on http; clean with HSTS', async () => {
  const probe = probeById('crypto-missing-hsts');
  assert.equal((await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', headers: {} }))).detected, true);
  assert.equal((await probe.evaluate(fakeCtx({ finalUrl: 'http://app.example/', headers: {} }))).detected, false);
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', headers: { 'strict-transport-security': 'max-age=600' } }))).detected,
    false,
  );
});

test('cookie-missing-secure: detected on https cookie without Secure; n/a on http', async () => {
  const probe = probeById('crypto-cookie-missing-secure');
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', cookies: [cookie({ secure: false })] }))).detected,
    true,
  );
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'http://app.example/', cookies: [cookie({ secure: false })] }))).detected,
    false,
  );
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', cookies: [cookie({ secure: true })] }))).detected,
    false,
  );
});

test('weak-tls-version: detected for TLS 1.0; clean for TLS 1.3; clean when details absent', async () => {
  const probe = probeById('crypto-weak-tls-version');
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', securityDetails: { protocol: 'TLS 1.0' } }))).detected,
    true,
  );
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', securityDetails: { protocol: 'TLS 1.3' } }))).detected,
    false,
  );
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', securityDetails: null }))).detected,
    false,
  );
});

test('mixed-content: detected for http subresource on https; clean on http page', async () => {
  const probe = probeById('crypto-mixed-content');
  const mixed = await probe.evaluate(
    fakeCtx({ finalUrl: 'https://app.example/', resources: [resource({ url: 'http://cdn.example/x.js' })] }),
  );
  assert.equal(mixed.detected, true);
  assert.match(mixed.evidence ?? '', /http:\/\/cdn\.example/);

  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'http://app.example/', resources: [resource({ url: 'http://cdn.example/x.js' })] }))).detected,
    false,
  );
  assert.equal(
    (await probe.evaluate(fakeCtx({ finalUrl: 'https://app.example/', resources: [resource({ url: 'https://cdn.example/x.js' })] }))).detected,
    false,
  );
});

// --- A08: Software/Data Integrity Failures --------------------------------

test('missing-sri: detected for cross-origin script without integrity; clean when same-origin or integrity present', async () => {
  const probe = probeById('integrity-missing-sri');

  const crossNoIntegrity = await probe.evaluate(
    fakeCtx({ finalUrl: 'https://app.example/', resources: [resource({ url: 'https://cdn.other.example/lib.js' })] }),
  );
  assert.equal(crossNoIntegrity.detected, true);

  const sameOrigin = await probe.evaluate(
    fakeCtx({ finalUrl: 'https://app.example/', resources: [resource({ url: 'https://app.example/lib.js' })] }),
  );
  assert.equal(sameOrigin.detected, false);

  const withIntegrity = await probe.evaluate(
    fakeCtx({
      finalUrl: 'https://app.example/',
      resources: [resource({ url: 'https://cdn.other.example/lib.js', integrity: 'sha384-abc' })],
    }),
  );
  assert.equal(withIntegrity.detected, false);

  const crossStylesheet = await probe.evaluate(
    fakeCtx({
      finalUrl: 'https://app.example/',
      resources: [resource({ tag: 'link', rel: 'stylesheet', url: 'https://cdn.other.example/s.css' })],
    }),
  );
  assert.equal(crossStylesheet.detected, true);

  // A cross-origin image does not need SRI → not flagged.
  const crossImage = await probe.evaluate(
    fakeCtx({ finalUrl: 'https://app.example/', resources: [resource({ tag: 'img', url: 'https://cdn.other.example/p.png' })] }),
  );
  assert.equal(crossImage.detected, false);
});

// --- A10: Mishandling of Exceptional Conditions ---------------------------

test('verbose-error: detected on 5xx; detected (High) on stack trace; clean on normal 200', async () => {
  const probe = probeById('exception-verbose-error');

  const serverError = await probe.evaluate(fakeCtx({ status: 503, html: '<html>Service Unavailable</html>' }));
  assert.equal(serverError.detected, true);

  const trace = await probe.evaluate(
    fakeCtx({ status: 200, html: '<pre>Traceback (most recent call last):\n  File "app.py", line 1</pre>' }),
  );
  assert.equal(trace.detected, true);
  assert.equal(trace.severity, 'High');

  const clean = await probe.evaluate(fakeCtx({ status: 200, html: '<html><body>welcome</body></html>' }));
  assert.equal(clean.detected, false);
});

// --- No false positives on a hardened page; Zod-valid Findings ------------

test('a hardened HTTPS page yields ZERO detections across all probes', async () => {
  const ctx = fakeCtx({
    finalUrl: 'https://app.example/',
    status: 200,
    headers: SECURE_HEADERS,
    cookies: [cookie({ secure: true, httpOnly: true, sameSite: 'Lax' })],
    securityDetails: { protocol: 'TLS 1.3' },
    resources: [resource({ url: 'https://app.example/app.js' })],
    html: '<!doctype html><html><body>welcome</body></html>',
  });
  for (const probe of WEB_PROBES) {
    const detection = await probe.evaluate(ctx);
    assert.equal(detection.detected, false, `false positive from probe ${probe.id}: ${detection.rationale}`);
    assert.ok(detection.rationale.length > 0, `probe ${probe.id} must always explain its decision`);
  }
});

test('each positive detection can build a Zod-valid Finding', async () => {
  // A deliberately weak HTTP page so several probes fire.
  const ctx = fakeCtx({
    finalUrl: 'http://app.example/',
    status: 500,
    headers: { 'x-powered-by': 'Express' },
    cookies: [cookie({ name: 'token', secure: false, httpOnly: false, sameSite: 'None' })],
    html: '<pre>Traceback (most recent call last):</pre>',
    resources: [resource({ url: 'http://cdn.other.example/lib.js' })],
  });

  let positives = 0;
  for (const probe of WEB_PROBES) {
    const detection = await probe.evaluate(ctx);
    if (!detection.detected) continue;
    positives += 1;
    const finding = findingSchema.parse({
      id: `web:${probe.id}`,
      severity: detection.severity ?? probe.severity,
      category: probe.category,
      title: probe.title,
      description: probe.description,
      evidence: { input: `GET ${ctx.finalUrl}`, output: detection.evidence ?? detection.rationale },
      recommendation: probe.recommendation,
    });
    assert.equal(finding.id, `web:${probe.id}`);
  }
  assert.ok(positives >= 4, `expected several positives on the weak page, got ${positives}`);
});
