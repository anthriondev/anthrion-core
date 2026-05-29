import { resolveNs } from 'node:dns/promises';

import type { TlsSecurityDetails } from './web-probe';
import type { Web3DAppTarget } from './web3-target';
import {
  BUNDLE_DRIFT_KNOWN_CDN_HOSTS,
  KNOWN_BAD_DOMAIN_LIST,
  NO_L2_RESULT,
  clipForEvidence,
  isCrossOriginResource,
  l2SriEligible,
  safeParseUrl,
  sha256Hex,
  type Web3L2CoverageNote,
  type Web3L2Detection,
  type Web3L2EvaluationResult,
  type Web3L2Probe,
} from './web3-l2-probe';

/**
 * Curated Web3 L2 probes (Sprint A3, T-A3.6).
 *
 * Three probes, one per L2 slug from `owaspWeb3CategorySchema`. Probes
 * consume `Web3DAppTarget extends PageContext` for the page-side surface
 * (html, resources, securityDetails) AND make SMALL, SCOPED outbound calls
 * for the CDN bundle-drift cross-check and DNS NS lookup. The DNSSEC /
 * WHOIS sub-checks the spec mentions are honestly skipped via
 * coverage-notes (no in-Node DNSSEC validator without a library, and the
 * user pinned hand-rolled-only).
 *
 * Honesty rules (mirror api-probes / web3-l1 / web3-l3):
 *  - "I checked and the indicator isn't present" returns an empty
 *    `detections` array; coverage notes are added separately when a
 *    sub-check could NOT be performed (CDN unreachable, DNS lookup
 *    failed, TLS details unavailable).
 *  - Negative findings are NOT emitted — silence is silence.
 *  - Evidence carries only the offending field(s), capped via
 *    `clipForEvidence`.
 *  - No probe ever throws under normal "I checked" paths.
 */

// ── 1. dapp-frontend-integrity ──────────────────────────────────────────────

/**
 * `web3:l2:dapp-frontend-integrity` — WA13 (T-A3.6).
 *
 * Two materially different sub-checks share the slug:
 *
 *  (a) **SRI absence per external script** — Medium. For every cross-origin
 *      `<script src>` (and `<link rel="stylesheet">`) embedded on the dApp
 *      page that omits an `integrity=` attribute, emit ONE detection. The
 *      spec is explicit: "SRI absence is reported per external script tag,
 *      not just one summary."
 *
 *  (b) **Bundle drift on a known immutable CDN** — High. For every
 *      cross-origin script served by a CDN whose URLs are version-pinned
 *      (unpkg / jsdelivr / cdnjs — `BUNDLE_DRIFT_KNOWN_CDN_HOSTS`), fetch
 *      the same URL fresh from the CDN, SHA-256 both the page-embedded
 *      content (if available via fetch) and the CDN-served content; a
 *      mismatch means the URL the page loaded does not equal what the CDN
 *      currently serves at that exact path. NB: we cannot directly read
 *      what the page actually loaded into Chromium (Playwright doesn't
 *      surface response bytes here); the probe fetches the URL TWICE
 *      (back-to-back) and flags only when the two fetches disagree — that
 *      catches a CDN serving a non-deterministic response for a pinned URL
 *      (a real drift class), without claiming to verify the in-page bytes.
 *
 * When a CDN host is reachable but a fetch fails (HTTP error, timeout),
 * the probe records a coverage note (`web3-l2-bundle-drift-fetch-failed`)
 * rather than inventing a finding.
 *
 * Per-detection severity overrides distinguish (a) from (b) in the report.
 */
const dappFrontendIntegrityProbe: Web3L2Probe = {
  id: 'web3:l2:dapp-frontend-integrity',
  technique: 'External script SRI / pinned-CDN bundle-drift cross-check',
  category: 'dapp-frontend-integrity',
  severity: 'Medium',
  title: 'dApp loads external frontend resources without integrity guarantees',
  description:
    "The dApp embeds a cross-origin script or stylesheet without an integrity (Subresource Integrity, SRI) attribute. If the third-party origin or CDN is compromised, the script the user's browser executes can be replaced — a wallet-drainer payload swapped onto a legitimate dApp is the canonical attack shape. This is an indicator, not a verdict; some dApps legitimately load from trusted same-control CDNs that are pinned by URL alone, but SRI is the standards-track way to make that contract explicit.",
  recommendation:
    'Add an integrity (SRI hash) and crossorigin attribute to every cross-origin <script> / <link rel="stylesheet"> the dApp loads, OR self-host the resource. For dependencies pinned to a version on unpkg / jsdelivr / cdnjs, generate the SRI hash from the immutable URL and include it in the embed.',
  async evaluate(target) {
    const pageUrl = safeParseUrl(target.finalUrl);
    const resources = await target.resources();
    if (resources.length === 0) {
      return NO_L2_RESULT;
    }
    const detections: Web3L2Detection[] = [];
    const coverageNotes: Web3L2CoverageNote[] = [];

    for (const res of resources) {
      if (!l2SriEligible(res.tag, res.rel)) continue;
      const resourceUrl = safeParseUrl(res.url);
      if (resourceUrl === undefined) continue;
      if (pageUrl !== undefined && !isCrossOriginResource(resourceUrl, pageUrl)) continue;

      // Sub-check (a): SRI absence.
      if (res.integrity === null || res.integrity.trim() === '') {
        detections.push({
          subjectKey: `sri-missing:${resourceUrl.toString()}`,
          severity: 'Medium',
          rationale: `${res.tag} ${resourceUrl.toString()} loads cross-origin without an integrity attribute.`,
          evidence: clipForEvidence(
            `tag=${res.tag}; src=${resourceUrl.toString()}; crossorigin=${res.crossorigin ?? '<absent>'}; integrity=<absent>.`,
          ),
          metadata: {
            subcheck: 'sri-absence',
            resourceUrl: resourceUrl.toString(),
            tag: res.tag,
          },
        });
      }

      // Sub-check (b): bundle-drift on known immutable CDNs.
      if (res.tag === 'script' && BUNDLE_DRIFT_KNOWN_CDN_HOSTS.has(resourceUrl.hostname)) {
        const driftDetection = await checkBundleDrift(resourceUrl, coverageNotes);
        if (driftDetection !== undefined) detections.push(driftDetection);
      }
    }

    return coverageNotes.length > 0 ? { detections, coverageNotes } : { detections };
  },
};

/**
 * Bundle-drift sub-check (b) implementation. Two back-to-back GET requests
 * to the same CDN URL; if the bytes differ, the CDN is serving a non-
 * deterministic response for what should be a version-pinned (immutable)
 * URL — the closest L2 has to a verdict signal. Returns `undefined` when
 * the indicator is not present (matched OR honest-not-reached); adds a
 * coverage note when fetching failed.
 */
async function checkBundleDrift(
  url: URL,
  coverageNotes: Web3L2CoverageNote[],
): Promise<Web3L2Detection | undefined> {
  let firstHash: string;
  let secondHash: string;
  try {
    firstHash = await fetchAndHash(url);
    secondHash = await fetchAndHash(url);
  } catch (cause) {
    coverageNotes.push({
      kind: 'web3-l2-bundle-drift-fetch-failed',
      reason: `Bundle-drift cross-check could not fetch ${url.hostname}${url.pathname}: ${shortError(cause)}.`,
    });
    return undefined;
  }
  if (firstHash === secondHash) return undefined;
  return {
    subjectKey: `bundle-drift:${url.toString()}`,
    severity: 'High',
    description:
      "The dApp embeds a script from a version-pinned CDN URL, but the CDN is serving a non-deterministic response for that exact URL — two back-to-back fetches returned different content. A pinned CDN URL is supposed to be immutable; drift here means either the CDN is compromised, the URL was not actually immutable, or the content the browser loaded may differ from what subsequent inspection sees.",
    rationale: `Two GETs of ${url.toString()} returned different SHA-256 hashes — the pinned CDN URL is not serving deterministic content.`,
    evidence: clipForEvidence(
      `src=${url.toString()}; firstSha256=${firstHash.slice(0, 16)}…; secondSha256=${secondHash.slice(0, 16)}…; pinned-CDN host=${url.hostname}.`,
    ),
    metadata: {
      subcheck: 'bundle-drift',
      resourceUrl: url.toString(),
      cdnHost: url.hostname,
      firstSha256: firstHash,
      secondSha256: secondHash,
    },
  };
}

async function fetchAndHash(url: URL): Promise<string> {
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'follow',
    headers: { 'user-agent': 'anthrion-l2-bundle-drift/1.0' },
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const buf = new Uint8Array(await response.arrayBuffer());
  return sha256Hex(buf);
}

// ── 2. known-bad-domain-reference ───────────────────────────────────────────

/**
 * `web3:l2:known-bad-domain-reference` — WA13 (T-A3.6).
 *
 * Walks every external resource URL (and the final page URL) the target
 * exposes, comparing the hostname against `KNOWN_BAD_DOMAIN_LIST`. Exact
 * lower-case hostname comparison (NOT substring) so `safe-wallet-drainer.com`
 * does not falsely match `wallet-drainer.com`. Emits ONE detection per
 * matched (hostname, source) pair so the report can point at exactly which
 * embed triggered the flag.
 *
 * Severity High. The hostname is a structural, verifiable fact; the
 * indicator-not-verdict framing lives in the description (a fork hosted on
 * a flagged domain is structurally identical to a phishing front — the
 * user is the one who decides which it is).
 */
const knownBadDomainReferenceProbe: Web3L2Probe = {
  id: 'web3:l2:known-bad-domain-reference',
  technique: 'Curated wallet-drainer / phishing host blocklist lookup',
  category: 'known-bad-domain-reference',
  severity: 'High',
  title: 'dApp references a host on the curated wallet-drainer / phishing blocklist',
  description:
    "The dApp page or one of the resources it embeds resolves to a hostname on our curated list of wallet-drainer / phishing fronts (Inferno Drainer family, Pink Drainer, look-alike wallet UIs, look-alike DEX routes). The list is small and hand-picked from public researcher writeups, so the absence of a match is NOT a clean bill — a host not on this list could still be malicious. But a hostname that IS on the list deserves the user's attention before they sign anything.",
  recommendation:
    'Do not connect a wallet to a dApp that references a known-bad host. If you believe the match is a false positive (e.g. a legitimate fork hosted on a re-used domain), verify through the project\'s independent channels (founder presence, audit reports) before approving anything.',
  evaluate(target) {
    const blocklist = new Set(KNOWN_BAD_DOMAIN_LIST.map((h) => h.toLowerCase()));
    const detections: Web3L2Detection[] = [];

    // Check the page's own final URL first.
    const pageUrl = safeParseUrl(target.finalUrl);
    if (pageUrl !== undefined && blocklist.has(pageUrl.hostname.toLowerCase())) {
      detections.push({
        subjectKey: `page-url:${pageUrl.hostname}`,
        rationale: `The dApp's own page URL hostname ${pageUrl.hostname} matches the curated blocklist.`,
        evidence: clipForEvidence(
          `pageUrl=${pageUrl.toString()}; matched hostname=${pageUrl.hostname.toLowerCase()}.`,
        ),
        metadata: { source: 'page-url', hostname: pageUrl.hostname.toLowerCase() },
      });
    }

    return target.resources().then((resources) => {
      for (const res of resources) {
        const url = safeParseUrl(res.url);
        if (url === undefined) continue;
        const host = url.hostname.toLowerCase();
        if (!blocklist.has(host)) continue;
        detections.push({
          subjectKey: `resource:${res.tag}:${url.toString()}`,
          rationale: `${res.tag} ${url.toString()} resolves to host ${host} which is on the curated blocklist.`,
          evidence: clipForEvidence(
            `tag=${res.tag}; src=${url.toString()}; matched hostname=${host}.`,
          ),
          metadata: { source: 'resource', tag: res.tag, hostname: host, resourceUrl: url.toString() },
        });
      }
      return { detections };
    });
  },
};

// ── 3. dapp-dns-or-tls-hygiene ──────────────────────────────────────────────

/**
 * `web3:l2:dapp-dns-or-tls-hygiene` — WA13 + partial WA02 (T-A3.6).
 *
 * Three TLS sub-checks + one DNS sub-check + an honest coverage note for
 * sub-checks we deliberately skip (DNSSEC validation, full WHOIS — both
 * require capabilities Node's built-ins do not expose, and the user pinned
 * hand-rolled-only).
 *
 * TLS sub-checks (consume `target.securityDetails()`):
 *  - **tls-missing-details** (Medium) — page IS HTTPS but the browser did
 *    not surface TLS details. Surfaced as a coverage note rather than a
 *    finding (we know the connection was TLS — Playwright proves that —
 *    but cannot inspect issuer/validity).
 *  - **tls-cert-near-expiry** (Medium) — `validTo` is within the next 14
 *    days. A certificate about to expire is operationally a real risk
 *    (sudden inability to load the dApp at the moment a user needs it),
 *    and a recently-renewed cert is the normal pattern; a cert nearly
 *    expired with no rotation activity is an indicator that the operator
 *    is inattentive.
 *  - **tls-cert-very-fresh** (Medium) — `validFrom` within the last 7 days
 *    on a dApp expected to be long-lived. Brand-new certificates are
 *    common in legitimate launches AND in phishing flows that spin up a
 *    look-alike domain just before a campaign.
 *
 * DNS sub-check (uses `node:dns/promises.resolveNs`):
 *  - **dns-ns-unresolvable** (Medium) — the apex domain's NS records
 *    cannot be resolved. A real working dApp resolves; failure here is a
 *    rare-but-flagworthy condition (in-flight DNS misconfiguration,
 *    suspicious takedown, etc.). DNSSEC validation is honestly skipped
 *    via a coverage note.
 */
const dappDnsOrTlsHygieneProbe: Web3L2Probe = {
  id: 'web3:l2:dapp-dns-or-tls-hygiene',
  technique: 'TLS issuer/validity inspection + DNS NS resolution health',
  category: 'dapp-dns-or-tls-hygiene',
  severity: 'Medium',
  title: 'dApp DNS or TLS hygiene indicator present',
  description:
    "The dApp's DNS or TLS posture exhibits a hygiene indicator: certificate near expiry / very fresh, missing TLS details on an HTTPS page, or NS records that could not be resolved. Each of these is an indicator, not a verdict — legitimate dApps occasionally rotate certificates or transition DNS providers — but they describe a posture where the user's trust assumption (that the dApp's identity and transport are stable) deserves a second look before signing.",
  recommendation:
    'Verify the dApp\'s domain ownership and certificate status via an independent channel (the project\'s official social presence, audit reports, deployment announcements) before granting wallet permissions. If the certificate is days-old or near-expiry, treat the connection with the same caution as a freshly-deployed contract.',
  async evaluate(target) {
    const detections: Web3L2Detection[] = [];
    const coverageNotes: Web3L2CoverageNote[] = [];

    // ── TLS sub-checks ──
    if (target.isHttps) {
      const details = await target.securityDetails();
      if (details === null) {
        coverageNotes.push({
          kind: 'web3-l2-tls-details-unavailable',
          reason: 'Page is HTTPS but the browser did not surface TLS details — TLS hygiene sub-checks were skipped for this scan.',
        });
      } else {
        const tlsDetections = inspectTlsHygiene(details);
        detections.push(...tlsDetections);
      }
    } else {
      coverageNotes.push({
        kind: 'web3-l2-tls-not-applicable',
        reason: 'dApp is not served over HTTPS — TLS hygiene sub-checks are not applicable. The lack of HTTPS is a separate concern reported by the standard web scan.',
      });
    }

    // ── DNS sub-check ──
    const pageUrl = safeParseUrl(target.finalUrl);
    if (pageUrl !== undefined) {
      try {
        const apex = pageUrl.hostname;
        const nameservers = await resolveNs(apex);
        if (nameservers.length === 0) {
          detections.push({
            subjectKey: `dns-ns-empty:${apex}`,
            rationale: `DNS NS query for ${apex} returned an empty nameserver list.`,
            evidence: clipForEvidence(`apex=${apex}; nameservers=[]; lookup returned but with zero entries.`),
            metadata: { subcheck: 'dns-ns-empty', apex },
          });
        }
      } catch (cause) {
        const hostname = pageUrl.hostname;
        detections.push({
          subjectKey: `dns-ns-unresolvable:${hostname}`,
          rationale: `DNS NS lookup for ${hostname} failed: ${shortError(cause)}.`,
          evidence: clipForEvidence(
            `apex=${hostname}; lookup=resolveNs; error=${shortError(cause)}.`,
          ),
          metadata: { subcheck: 'dns-ns-unresolvable', apex: hostname },
        });
      }
    }

    // Honest skip note: DNSSEC validation requires capabilities Node's
    // built-in dns module does not expose, and the user pinned hand-rolled-only.
    coverageNotes.push({
      kind: 'web3-l2-dnssec-skipped',
      reason: 'DNSSEC validation requires a DNSSEC-aware resolver and is out of scope for the Phase 1 hand-rolled L2 probe; sub-check honestly skipped.',
    });

    return coverageNotes.length > 0 ? { detections, coverageNotes } : { detections };
  },
};

const NEAR_EXPIRY_WINDOW_DAYS = 14;
const VERY_FRESH_WINDOW_DAYS = 7;

function inspectTlsHygiene(details: TlsSecurityDetails): Web3L2Detection[] {
  const detections: Web3L2Detection[] = [];
  const nowSec = Math.floor(Date.now() / 1000);
  const dayInSec = 24 * 60 * 60;

  if (details.validTo !== undefined) {
    const ageSeconds = details.validTo - nowSec;
    if (ageSeconds <= NEAR_EXPIRY_WINDOW_DAYS * dayInSec && ageSeconds > 0) {
      const daysLeft = Math.floor(ageSeconds / dayInSec);
      detections.push({
        subjectKey: 'tls-cert-near-expiry',
        rationale: `TLS certificate expires in ${daysLeft} day(s) — within the ${NEAR_EXPIRY_WINDOW_DAYS}-day hygiene window.`,
        evidence: clipForEvidence(
          `validTo=${details.validTo} (unix); daysLeft=${daysLeft}; issuer=${details.issuer ?? '<unknown>'}; subjectName=${details.subjectName ?? '<unknown>'}.`,
        ),
        metadata: {
          subcheck: 'tls-cert-near-expiry',
          validTo: String(details.validTo),
          daysLeft: String(daysLeft),
          ...(details.issuer !== undefined ? { issuer: details.issuer } : {}),
        },
      });
    }
  }

  if (details.validFrom !== undefined) {
    const ageSeconds = nowSec - details.validFrom;
    if (ageSeconds <= VERY_FRESH_WINDOW_DAYS * dayInSec && ageSeconds >= 0) {
      const daysOld = Math.floor(ageSeconds / dayInSec);
      detections.push({
        subjectKey: 'tls-cert-very-fresh',
        rationale: `TLS certificate was issued ${daysOld} day(s) ago — within the ${VERY_FRESH_WINDOW_DAYS}-day fresh-cert hygiene window.`,
        evidence: clipForEvidence(
          `validFrom=${details.validFrom} (unix); daysOld=${daysOld}; issuer=${details.issuer ?? '<unknown>'}; subjectName=${details.subjectName ?? '<unknown>'}.`,
        ),
        metadata: {
          subcheck: 'tls-cert-very-fresh',
          validFrom: String(details.validFrom),
          daysOld: String(daysOld),
          ...(details.issuer !== undefined ? { issuer: details.issuer } : {}),
        },
      });
    }
  }

  return detections;
}

function shortError(cause: unknown): string {
  if (cause instanceof Error) {
    return cause.message.length > 120 ? `${cause.message.slice(0, 117)}...` : cause.message;
  }
  return String(cause).slice(0, 120);
}

// ── Export the curated probe set ────────────────────────────────────────────

/**
 * The three L2 probes, in display order. Order is stable for deterministic
 * reporting; frozen so callers cannot mutate the curated set.
 *
 * Slug coverage (matches `owaspWeb3CategorySchema` L2 block exactly):
 *  - dapp-frontend-integrity
 *  - known-bad-domain-reference
 *  - dapp-dns-or-tls-hygiene
 */
export const WEB3_L2_PROBES: readonly Web3L2Probe[] = Object.freeze([
  dappFrontendIntegrityProbe,
  knownBadDomainReferenceProbe,
  dappDnsOrTlsHygieneProbe,
]);
