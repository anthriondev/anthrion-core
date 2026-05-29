import { notDetected, type PageContext, type PageResource, type WebDetection, type WebProbe } from './web-probe';

/**
 * Concrete DAST probes for the web app vulnerability scan (T2.6, Part A.3).
 *
 * Every probe here is a REAL, rule-based, LLM-free check that observes what
 * Chromium loaded for one page. NO FAKE PROBES (Context §2): each only exists for a
 * `covered` category in `WEB_COVERAGE_MAP`, and each can genuinely detect its
 * issue. Categories that single-page DAST cannot honestly test have NO probe and
 * stay `phase-2` in the coverage map — consistency is enforced by tests.
 *
 * Detection technique per category:
 * - A02 security-misconfiguration — inspect response headers (security headers,
 *   CORS, software/version disclosure) and cookie flags.
 * - A04 cryptographic-failures — inspect transport (HTTP vs HTTPS, HSTS, negotiated
 *   TLS version), the cookie Secure flag, and mixed content.
 * - A08 software-or-data-integrity-failures — inspect the DOM for cross-origin
 *   subresources loaded without Subresource Integrity.
 * - A10 mishandling-of-exceptional-conditions — inspect the response status and
 *   body for server errors / verbose stack traces / framework debug pages.
 */

/** Cap on an evidence snippet so findings stay size-bounded. */
const EVIDENCE_SNIPPET_MAX = 400;

function snippet(value: string): string {
  return value.length <= EVIDENCE_SNIPPET_MAX ? value : `${value.slice(0, EVIDENCE_SNIPPET_MAX)}…`;
}

/** Parse a URL's origin, or null if it is not a parseable absolute URL. */
function safeOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function header(ctx: PageContext, name: string): string | undefined {
  return ctx.responseHeaders[name.toLowerCase()];
}

// --- A02: Security Misconfiguration ---------------------------------------

const missingCsp: WebProbe = {
  id: 'misconfig-missing-csp',
  technique: 'security-header-absent:content-security-policy',
  category: 'security-misconfiguration',
  severity: 'Medium',
  title: 'Missing Content-Security-Policy',
  description:
    'The page does not send a Content-Security-Policy. CSP is the primary defence-in-depth control against XSS and content injection; without it, injected scripts run unrestricted.',
  recommendation:
    'Send a Content-Security-Policy header with a restrictive policy (e.g. default-src \'self\'); avoid unsafe-inline/unsafe-eval.',
  async evaluate(ctx) {
    if (header(ctx, 'content-security-policy') !== undefined) {
      return notDetected('Content-Security-Policy header is present.');
    }
    // A CSP may also be delivered via a <meta http-equiv> tag — check before flagging.
    const html = await ctx.html();
    if (/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy/i.test(html)) {
      return notDetected('Content-Security-Policy delivered via a <meta http-equiv> tag.');
    }
    return {
      detected: true,
      rationale: 'No Content-Security-Policy delivered via header or <meta http-equiv>.',
      evidence: 'Response has no Content-Security-Policy header and no CSP <meta http-equiv> tag.',
    };
  },
};

const missingXContentTypeOptions: WebProbe = {
  id: 'misconfig-missing-x-content-type-options',
  technique: 'security-header-absent:x-content-type-options',
  category: 'security-misconfiguration',
  severity: 'Low',
  title: 'Missing X-Content-Type-Options: nosniff',
  description:
    'Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and interpret them as a different content type, enabling some injection/drive-by attacks.',
  recommendation: 'Send the header X-Content-Type-Options: nosniff on all responses.',
  async evaluate(ctx) {
    const value = header(ctx, 'x-content-type-options');
    if (value !== undefined && value.trim().toLowerCase() === 'nosniff') {
      return notDetected('X-Content-Type-Options is set to nosniff.');
    }
    return {
      detected: true,
      rationale:
        value === undefined
          ? 'X-Content-Type-Options header is absent.'
          : `X-Content-Type-Options is "${value}", not "nosniff".`,
      evidence: value === undefined ? 'header absent' : `x-content-type-options: ${value}`,
    };
  },
};

const missingXFrameOptions: WebProbe = {
  id: 'misconfig-missing-x-frame-options',
  technique: 'security-header-absent:clickjacking-protection',
  category: 'security-misconfiguration',
  severity: 'Medium',
  title: 'Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)',
  description:
    'The page can be embedded in a frame by any origin, enabling clickjacking. Protection requires X-Frame-Options or a Content-Security-Policy frame-ancestors directive.',
  recommendation:
    'Send X-Frame-Options: DENY (or SAMEORIGIN), or a CSP with frame-ancestors \'none\' (or \'self\').',
  async evaluate(ctx) {
    const xfo = header(ctx, 'x-frame-options');
    if (xfo !== undefined) {
      return notDetected(`Clickjacking protection present via X-Frame-Options: ${xfo}.`);
    }
    const csp = header(ctx, 'content-security-policy');
    if (csp !== undefined && /frame-ancestors/i.test(csp)) {
      return notDetected('Clickjacking protection present via CSP frame-ancestors directive.');
    }
    return {
      detected: true,
      rationale: 'No X-Frame-Options header and no CSP frame-ancestors directive.',
      evidence: 'Response has neither X-Frame-Options nor a CSP frame-ancestors directive.',
    };
  },
};

const missingReferrerPolicy: WebProbe = {
  id: 'misconfig-missing-referrer-policy',
  technique: 'security-header-absent:referrer-policy',
  category: 'security-misconfiguration',
  severity: 'Low',
  title: 'Missing Referrer-Policy',
  description:
    'Without a Referrer-Policy, the full URL (which may contain sensitive path/query data) can leak to third-party destinations via the Referer header.',
  recommendation: 'Send a Referrer-Policy header (e.g. strict-origin-when-cross-origin or no-referrer).',
  async evaluate(ctx) {
    const value = header(ctx, 'referrer-policy');
    if (value !== undefined) {
      return notDetected(`Referrer-Policy is set: ${value}.`);
    }
    return {
      detected: true,
      rationale: 'Referrer-Policy header is absent.',
      evidence: 'header absent',
    };
  },
};

const permissiveCors: WebProbe = {
  id: 'misconfig-permissive-cors',
  technique: 'cors-acao-wildcard',
  category: 'security-misconfiguration',
  severity: 'Medium',
  title: 'Permissive CORS policy (Access-Control-Allow-Origin: *)',
  description:
    'The response allows any origin to read it via CORS. If the resource is sensitive, this exposes it cross-origin. Combined with credentialed requests it is a serious data-exposure risk.',
  recommendation:
    'Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins; never combine a wildcard (or reflected origin) with Access-Control-Allow-Credentials: true.',
  async evaluate(ctx) {
    const acao = header(ctx, 'access-control-allow-origin');
    if (acao === undefined || acao.trim() !== '*') {
      return notDetected(
        acao === undefined
          ? 'No Access-Control-Allow-Origin header (CORS not enabled for this response).'
          : `Access-Control-Allow-Origin is "${acao}", not a wildcard.`,
      );
    }
    const credentials = header(ctx, 'access-control-allow-credentials');
    const withCredentials = credentials !== undefined && credentials.trim().toLowerCase() === 'true';
    return {
      detected: true,
      rationale: withCredentials
        ? 'Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.'
        : 'Access-Control-Allow-Origin: * (any origin may read the response).',
      evidence: `access-control-allow-origin: *${withCredentials ? '; access-control-allow-credentials: true' : ''}`,
      ...(withCredentials ? { severity: 'High' as const } : {}),
    };
  },
};

const softwareDisclosure: WebProbe = {
  id: 'misconfig-software-disclosure',
  technique: 'server-software-version-disclosure',
  category: 'security-misconfiguration',
  severity: 'Low',
  title: 'Server software / version disclosure',
  description:
    'Response headers disclose the server software stack (and sometimes its version), aiding an attacker in fingerprinting and targeting known vulnerabilities.',
  recommendation: 'Suppress or genericise the Server and X-Powered-By response headers.',
  async evaluate(ctx) {
    const disclosures: string[] = [];
    const poweredBy = header(ctx, 'x-powered-by');
    if (poweredBy !== undefined) {
      disclosures.push(`x-powered-by: ${poweredBy}`);
    }
    const server = header(ctx, 'server');
    // Flag Server only when it reveals a version (e.g. "Apache/2.4.41"); a bare
    // product name like "cloudflare" is normal and not worth a finding.
    if (server !== undefined && /\d/.test(server) && /[/ ]/.test(server)) {
      disclosures.push(`server: ${server}`);
    }
    if (disclosures.length === 0) {
      return notDetected('No Server version or X-Powered-By disclosure observed.');
    }
    return {
      detected: true,
      rationale: 'Response headers disclose the server software stack.',
      evidence: snippet(disclosures.join('; ')),
    };
  },
};

const cookieMissingHttpOnly: WebProbe = {
  id: 'misconfig-cookie-missing-httponly',
  technique: 'cookie-flag-absent:httponly',
  category: 'security-misconfiguration',
  severity: 'Low',
  title: 'Cookie without HttpOnly flag',
  description:
    'One or more cookies are accessible to JavaScript (no HttpOnly flag). If the site has an XSS flaw, such cookies (e.g. session tokens) can be stolen.',
  recommendation: 'Set the HttpOnly flag on cookies that do not need JavaScript access (especially session cookies).',
  async evaluate(ctx) {
    const cookies = await ctx.cookies();
    if (cookies.length === 0) {
      return notDetected('No cookies set for the page.');
    }
    const offenders = cookies.filter((c) => !c.httpOnly).map((c) => c.name);
    if (offenders.length === 0) {
      return notDetected('All cookies have the HttpOnly flag.');
    }
    return {
      detected: true,
      rationale: `${offenders.length} cookie(s) lack the HttpOnly flag.`,
      evidence: snippet(`Cookies without HttpOnly: ${offenders.join(', ')}`),
    };
  },
};

const cookieSameSiteNoneInsecure: WebProbe = {
  id: 'misconfig-cookie-samesite-none-insecure',
  technique: 'cookie-samesite-none-without-secure',
  category: 'security-misconfiguration',
  severity: 'Medium',
  title: 'Cookie with SameSite=None but no Secure flag',
  description:
    'A cookie declares SameSite=None (sent on cross-site requests) without the Secure flag. Browsers require Secure for SameSite=None; such a cookie is also transmittable over plaintext, exposing it to interception and CSRF.',
  recommendation: 'Any cookie with SameSite=None MUST also set Secure. Prefer SameSite=Lax/Strict where cross-site use is not needed.',
  async evaluate(ctx) {
    const cookies = await ctx.cookies();
    const offenders = cookies.filter((c) => c.sameSite === 'None' && !c.secure).map((c) => c.name);
    if (offenders.length === 0) {
      return notDetected('No SameSite=None cookies missing the Secure flag.');
    }
    return {
      detected: true,
      rationale: `${offenders.length} cookie(s) use SameSite=None without Secure.`,
      evidence: snippet(`SameSite=None without Secure: ${offenders.join(', ')}`),
    };
  },
};

// --- A04: Cryptographic Failures ------------------------------------------

const noHttps: WebProbe = {
  id: 'crypto-no-https',
  technique: 'transport-cleartext-http',
  category: 'cryptographic-failures',
  severity: 'High',
  title: 'Site served over plaintext HTTP',
  description:
    'The page is served over HTTP, so all data (including any credentials, tokens, or cookies) travels in cleartext and can be read or modified by a network attacker.',
  recommendation: 'Serve the site exclusively over HTTPS and redirect HTTP to HTTPS; then add HSTS.',
  async evaluate(ctx) {
    if (ctx.isHttps) {
      return notDetected('Final URL is served over HTTPS.');
    }
    return {
      detected: true,
      rationale: `Final URL uses a non-HTTPS scheme: ${ctx.finalUrl}.`,
      evidence: `Served over plaintext: ${ctx.finalUrl}`,
    };
  },
};

const missingHsts: WebProbe = {
  id: 'crypto-missing-hsts',
  technique: 'security-header-absent:strict-transport-security',
  category: 'cryptographic-failures',
  severity: 'Medium',
  title: 'Missing HTTP Strict-Transport-Security (HSTS)',
  description:
    'The HTTPS site does not send Strict-Transport-Security, so browsers are not told to enforce HTTPS. This leaves users exposed to SSL-stripping / downgrade on the first or subsequent visits.',
  recommendation: 'Send Strict-Transport-Security with a long max-age (e.g. max-age=31536000; includeSubDomains).',
  async evaluate(ctx) {
    if (!ctx.isHttps) {
      // HSTS is ignored by browsers when sent over HTTP; the no-https probe owns this case.
      return notDetected('Page is not served over HTTPS; HSTS is not applicable (see crypto-no-https).');
    }
    if (header(ctx, 'strict-transport-security') !== undefined) {
      return notDetected('Strict-Transport-Security header is present.');
    }
    return {
      detected: true,
      rationale: 'HTTPS response has no Strict-Transport-Security header.',
      evidence: 'header absent on HTTPS response',
    };
  },
};

const cookieMissingSecure: WebProbe = {
  id: 'crypto-cookie-missing-secure',
  technique: 'cookie-flag-absent:secure',
  category: 'cryptographic-failures',
  severity: 'Medium',
  title: 'Cookie without Secure flag on HTTPS site',
  description:
    'A cookie on an HTTPS site lacks the Secure flag, so it can be transmitted over a plaintext HTTP connection and intercepted (e.g. via a downgrade).',
  recommendation: 'Set the Secure flag on all cookies served by an HTTPS site.',
  async evaluate(ctx) {
    if (!ctx.isHttps) {
      return notDetected('Page is not served over HTTPS; the Secure flag is assessed only for HTTPS sites.');
    }
    const cookies = await ctx.cookies();
    if (cookies.length === 0) {
      return notDetected('No cookies set for the page.');
    }
    const offenders = cookies.filter((c) => !c.secure).map((c) => c.name);
    if (offenders.length === 0) {
      return notDetected('All cookies have the Secure flag.');
    }
    return {
      detected: true,
      rationale: `${offenders.length} cookie(s) on an HTTPS site lack the Secure flag.`,
      evidence: snippet(`Cookies without Secure: ${offenders.join(', ')}`),
    };
  },
};

/** TLS protocol strings considered weak/deprecated. */
const WEAK_TLS = /\b(?:SSL\s?v?[23]|TLS\s?1\.0|TLS\s?1\.1|TLSv1\.0|TLSv1\.1)\b/i;

const weakTls: WebProbe = {
  id: 'crypto-weak-tls-version',
  technique: 'tls-deprecated-protocol-version',
  category: 'cryptographic-failures',
  severity: 'High',
  title: 'Weak/deprecated TLS protocol version',
  description:
    'The HTTPS connection negotiated a deprecated TLS/SSL version (SSLv2/3, TLS 1.0/1.1). These have known cryptographic weaknesses and are disallowed by current standards.',
  recommendation: 'Disable SSLv2/v3 and TLS 1.0/1.1; require TLS 1.2 or higher.',
  async evaluate(ctx) {
    if (!ctx.isHttps) {
      return notDetected('Page is not served over HTTPS; no TLS version to assess.');
    }
    const details = await ctx.securityDetails();
    if (details === null || details.protocol === undefined) {
      return notDetected('Negotiated TLS protocol was not reported by the browser; not assessed.');
    }
    if (WEAK_TLS.test(details.protocol)) {
      return {
        detected: true,
        rationale: `Connection negotiated a deprecated protocol: ${details.protocol}.`,
        evidence: `TLS protocol: ${details.protocol}`,
      };
    }
    return notDetected(`Negotiated TLS protocol is acceptable: ${details.protocol}.`);
  },
};

const mixedContent: WebProbe = {
  id: 'crypto-mixed-content',
  technique: 'mixed-content-http-subresource',
  category: 'cryptographic-failures',
  severity: 'Medium',
  title: 'Mixed content (HTTP subresources on an HTTPS page)',
  description:
    'An HTTPS page references subresources over plaintext HTTP. Mixed content can be intercepted or tampered with, undermining the security of the HTTPS page.',
  recommendation: 'Load all subresources over HTTPS; add a Content-Security-Policy with upgrade-insecure-requests.',
  async evaluate(ctx) {
    if (!ctx.isHttps) {
      return notDetected('Page is not served over HTTPS; mixed content is not applicable.');
    }
    const resources = await ctx.resources();
    const offenders = resources
      .filter((r) => r.url.startsWith('http://'))
      .map((r) => `${r.tag}: ${r.url}`);
    if (offenders.length === 0) {
      return notDetected('No HTTP subresources referenced from the HTTPS page.');
    }
    return {
      detected: true,
      rationale: `${offenders.length} subresource(s) loaded over plaintext HTTP.`,
      evidence: snippet(offenders.join('; ')),
    };
  },
};

// --- A08: Software or Data Integrity Failures -----------------------------

/** Returns true if the resource is a script/stylesheet that should carry SRI. */
function sriEligible(r: PageResource): boolean {
  if (r.tag === 'script') return true;
  if (r.tag === 'link') return r.rel === 'stylesheet';
  return false;
}

const missingSri: WebProbe = {
  id: 'integrity-missing-sri',
  technique: 'subresource-integrity-absent',
  category: 'software-or-data-integrity-failures',
  severity: 'Medium',
  title: 'Cross-origin resource loaded without Subresource Integrity',
  description:
    'The page loads cross-origin scripts/stylesheets without an integrity attribute. If the third-party origin (or CDN) is compromised, malicious code executes with the page\'s privileges — a software/data integrity failure.',
  recommendation:
    'Add an integrity (SRI hash) and crossorigin attribute to cross-origin <script>/<link rel="stylesheet"> elements, or self-host them.',
  async evaluate(ctx) {
    const pageOrigin = safeOrigin(ctx.finalUrl);
    const resources = await ctx.resources();
    const offenders: string[] = [];
    for (const r of resources) {
      if (!sriEligible(r)) continue;
      const origin = safeOrigin(r.url);
      // Only cross-origin resources need SRI; skip same-origin and unparseable URLs.
      if (origin === null || origin === pageOrigin) continue;
      if (r.integrity === null || r.integrity.trim() === '') {
        offenders.push(`${r.tag}: ${r.url}`);
      }
    }
    if (offenders.length === 0) {
      return notDetected('No cross-origin scripts/stylesheets without Subresource Integrity.');
    }
    return {
      detected: true,
      rationale: `${offenders.length} cross-origin resource(s) loaded without an integrity attribute.`,
      evidence: snippet(offenders.join('; ')),
    };
  },
};

// --- A10: Mishandling of Exceptional Conditions ---------------------------

/** Specific debug/stack-trace/error signatures (kept specific to limit false positives). */
const ERROR_SIGNATURES: readonly { label: string; re: RegExp }[] = [
  { label: 'python-traceback', re: /Traceback \(most recent call last\):/ },
  { label: 'werkzeug-debugger', re: /Werkzeug Debugger|werkzeug\.debug|class="traceback"/i },
  { label: 'laravel-whoops', re: /Whoops\\\\|Whoops, looks like something went wrong/i },
  { label: 'rails-error', re: /ActionController::|<title>Action Controller: Exception caught/i },
  { label: 'aspnet-error', re: /Server Error in '.*' Application|<b>Stack Trace:<\/b>/i },
  { label: 'java-stacktrace', re: /(?:^|\n)\s*at [\w.$]+\([\w.]+\.java:\d+\)|Caused by: [\w.$]+Exception/ },
  { label: 'php-fatal', re: /Fatal error<\/b>:|PHP (?:Warning|Fatal error):.* on line \d+/i },
  { label: 'sql-error', re: /You have an error in your SQL syntax|SQLSTATE\[|Unclosed quotation mark after the character string|ORA-\d{5}/i },
  { label: 'dotnet-yellow-screen', re: /Runtime Error<\/span>|Description:.*An (?:application|unhandled) (?:error|exception) occurred/i },
];

const verboseError: WebProbe = {
  id: 'exception-verbose-error',
  technique: 'verbose-error-or-stacktrace-disclosure',
  category: 'mishandling-of-exceptional-conditions',
  severity: 'Medium',
  title: 'Verbose error / stack trace disclosure',
  description:
    'The scanned response reveals a mishandled exceptional condition — a server error returned to the user and/or a verbose stack trace / framework debug page. Such pages leak internal paths, stack frames, and component versions that aid an attacker.',
  recommendation:
    'Disable debug mode in production; return generic error pages; log exception detail server-side only.',
  async evaluate(ctx) {
    const html = await ctx.html();
    const matched = ERROR_SIGNATURES.find((s) => s.re.test(html));
    const serverError = ctx.status >= 500 && ctx.status <= 599;

    if (matched !== undefined) {
      const snippetMatch = matched.re.exec(html);
      return {
        detected: true,
        // A leaked stack trace/debug page exposes internals → escalate to High.
        severity: 'High',
        rationale: `Response body matches a known debug/stack-trace signature (${matched.label})${serverError ? ` and returned HTTP ${ctx.status}` : ''}.`,
        evidence: snippet(snippetMatch !== null ? snippetMatch[0] : matched.label),
        metadata: { signature: matched.label, httpStatus: String(ctx.status) },
      };
    }
    if (serverError) {
      return {
        detected: true,
        rationale: `Scanned URL returned a server error: HTTP ${ctx.status}.`,
        evidence: `HTTP ${ctx.status}`,
        metadata: { httpStatus: String(ctx.status) },
      };
    }
    return notDetected(`No server error (HTTP ${ctx.status}) or debug/stack-trace signature in the response.`);
  },
};

/**
 * The default DAST probe set. Order is presentation order (most severe transport
 * issue first, then misconfiguration, integrity, exceptional conditions). Each
 * probe maps to a `covered` category in `WEB_COVERAGE_MAP`.
 */
export const WEB_PROBES: readonly WebProbe[] = [
  // A04 Cryptographic failures
  noHttps,
  missingHsts,
  cookieMissingSecure,
  weakTls,
  mixedContent,
  // A02 Security misconfiguration
  missingCsp,
  missingXFrameOptions,
  missingXContentTypeOptions,
  missingReferrerPolicy,
  permissiveCors,
  softwareDisclosure,
  cookieMissingHttpOnly,
  cookieSameSiteNoneInsecure,
  // A08 Software/data integrity failures
  missingSri,
  // A10 Mishandling of exceptional conditions
  verboseError,
] as const;

export type { WebDetection };
