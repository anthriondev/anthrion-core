import type { BrowserContext, Page, Response } from 'playwright';
import { z } from 'zod';

import {
  pageResourceSchema,
  type ObservedCookie,
  type PageContext,
  type PageResource,
  type TlsSecurityDetails,
} from './web-probe';

/**
 * Playwright-backed `PageContext` (T2.6). Wraps a `Page` + its captured main
 * navigation `Response`, exposing exactly what probes need.
 *
 * Async accessors are MEMOIZED: cookies, TLS details, HTML, and DOM resources are
 * each fetched at most once and shared across all probes — N probes do not cause N
 * browser round-trips. A memoized promise is kept even if a probe times out
 * waiting on it; the underlying Chromium call may still settle and serve the next
 * probe from cache.
 */

/** Cap on captured HTML so a hostile/huge page cannot blow up memory or probes. */
export const HTML_CAPTURE_MAX = 1_000_000; // 1 MB of HTML is ample for detection.

/**
 * Browser-side extraction script (runs in the page via `page.evaluate`). Returns
 * the page's DOM-referenced subresources. Passed as a STRING so this Node package
 * does not need the DOM lib; the returned value is untrusted page data and is
 * Zod-validated (`pageResourceSchema`) before use (CLAUDE.md §3).
 */
const RESOURCE_EXTRACTION_SCRIPT = `(() => {
  const out = [];
  for (const s of Array.from(document.querySelectorAll('script[src]'))) {
    out.push({ tag: 'script', url: s.src || '', rel: null, integrity: s.getAttribute('integrity'), crossorigin: s.getAttribute('crossorigin') });
  }
  for (const l of Array.from(document.querySelectorAll('link[href]'))) {
    out.push({ tag: 'link', url: l.href || '', rel: (l.getAttribute('rel') || '').toLowerCase() || null, integrity: l.getAttribute('integrity'), crossorigin: l.getAttribute('crossorigin') });
  }
  for (const i of Array.from(document.querySelectorAll('img[src]'))) {
    out.push({ tag: 'img', url: i.src || '', rel: null, integrity: null, crossorigin: i.getAttribute('crossorigin') });
  }
  for (const f of Array.from(document.querySelectorAll('iframe[src]'))) {
    out.push({ tag: 'iframe', url: f.src || '', rel: null, integrity: null, crossorigin: null });
  }
  return out;
})()`;

const resourcesSchema = z.array(pageResourceSchema);

export class PlaywrightPageContext implements PageContext {
  readonly requestedUrl: string;
  readonly finalUrl: string;
  readonly status: number;
  readonly responseHeaders: Readonly<Record<string, string>>;
  readonly isHttps: boolean;

  private cookiesPromise: Promise<readonly ObservedCookie[]> | undefined;
  private securityPromise: Promise<TlsSecurityDetails | null> | undefined;
  private htmlPromise: Promise<string> | undefined;
  private resourcesPromise: Promise<readonly PageResource[]> | undefined;

  constructor(
    private readonly page: Page,
    private readonly response: Response,
    requestedUrl: string,
  ) {
    this.requestedUrl = requestedUrl;
    this.finalUrl = page.url();
    this.status = response.status();
    this.responseHeaders = lowerCaseKeys(response.headers());
    this.isHttps = this.finalUrl.startsWith('https:');
  }

  cookies(): Promise<readonly ObservedCookie[]> {
    if (this.cookiesPromise === undefined) {
      this.cookiesPromise = this.loadCookies();
    }
    return this.cookiesPromise;
  }

  private async loadCookies(): Promise<readonly ObservedCookie[]> {
    const context: BrowserContext = this.page.context();
    const raw = await context.cookies(this.finalUrl);
    return raw.map((c) => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
    }));
  }

  securityDetails(): Promise<TlsSecurityDetails | null> {
    if (this.securityPromise === undefined) {
      this.securityPromise = this.loadSecurityDetails();
    }
    return this.securityPromise;
  }

  private async loadSecurityDetails(): Promise<TlsSecurityDetails | null> {
    const details = await this.response.securityDetails();
    if (details === null) {
      return null;
    }
    // Copy only the fields we model; omit absent ones (exactOptionalPropertyTypes).
    const out: TlsSecurityDetails = {};
    if (details.protocol !== undefined) out.protocol = details.protocol;
    if (details.issuer !== undefined) out.issuer = details.issuer;
    if (details.subjectName !== undefined) out.subjectName = details.subjectName;
    if (details.validFrom !== undefined) out.validFrom = details.validFrom;
    if (details.validTo !== undefined) out.validTo = details.validTo;
    return out;
  }

  html(): Promise<string> {
    if (this.htmlPromise === undefined) {
      this.htmlPromise = this.loadHtml();
    }
    return this.htmlPromise;
  }

  private async loadHtml(): Promise<string> {
    const content = await this.page.content();
    return content.length > HTML_CAPTURE_MAX ? content.slice(0, HTML_CAPTURE_MAX) : content;
  }

  resources(): Promise<readonly PageResource[]> {
    if (this.resourcesPromise === undefined) {
      this.resourcesPromise = this.loadResources();
    }
    return this.resourcesPromise;
  }

  private async loadResources(): Promise<readonly PageResource[]> {
    // Untrusted page DOM → returned as `unknown`, validated with Zod before use.
    const raw: unknown = await this.page.evaluate(RESOURCE_EXTRACTION_SCRIPT);
    const parsed = resourcesSchema.safeParse(raw);
    if (!parsed.success) {
      // A malformed DOM extraction is not a vulnerability signal; treat as "no
      // resources observed" rather than crashing the whole scan.
      return [];
    }
    return parsed.data;
  }
}

/** Lower-case all header keys for case-insensitive lookups by probes. */
function lowerCaseKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}
