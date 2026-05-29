import { chromium, type Browser } from 'playwright';

/**
 * Render report HTML to a PDF buffer with Playwright `page.pdf()` (T6.1, locked
 * decision: Playwright/Chromium — reuse the worker's existing Chromium, same as the
 * web vuln scan T2.6; do NOT add a separate PDF library).
 *
 * The `page.pdf()` options were taken from the installed Playwright `.d.ts`
 * (playwright-core 1.60.0, CLAUDE.md §6): it returns a `Buffer`; `printBackground`
 * makes the dark void background + semantic colours render; `preferCSSPageSize` lets the
 * template's `@page` (A4 + margins) drive the page geometry. Launch args mirror
 * `DEFAULT_LAUNCH_ARGS` from the web scan so Chromium starts in the same constrained
 * environment.
 */

/** Launch args matching the web scan (scan-engine `DEFAULT_LAUNCH_ARGS`). */
const DEFAULT_LAUNCH_ARGS: readonly string[] = ['--no-sandbox', '--disable-dev-shm-usage'];

/** Page-margin box (any CSS length unit). When omitted, Chromium uses its default. */
export interface PdfMargin {
  top: string;
  right: string;
  bottom: string;
  left: string;
}

export interface RenderReportPdfOptions {
  /** Reuse an existing browser (caller owns its lifecycle). When omitted, one is launched and closed. */
  browser?: Browser;
  /** Chromium launch args when launching our own browser. Defaults to `DEFAULT_LAUNCH_ARGS`. */
  launchArgs?: readonly string[];
  /**
   * Running header/footer templates (T-POLISH.2). When BOTH are provided, `page.pdf()` is
   * called with `displayHeaderFooter: true` so they render in the page-margin band on every
   * page. They are ISOLATED documents (own CSS/fonts) — see `report-template.ts`.
   */
  headerTemplate?: string;
  footerTemplate?: string;
  /**
   * Page margins — the SINGLE geometry source when set (we drop `preferCSSPageSize` so the
   * body `@page` margin never double-applies). Sized to the header/footer band heights so the
   * bands sit flush to the page edges. When omitted, the body `@page` CSS drives geometry.
   */
  margin?: PdfMargin;
}

export async function renderReportPdf(html: string, options: RenderReportPdfOptions = {}): Promise<Buffer> {
  const ownBrowser = options.browser === undefined;
  const browser =
    options.browser ??
    (await chromium.launch({ headless: true, args: [...(options.launchArgs ?? DEFAULT_LAUNCH_ARGS)] }));

  const displayHeaderFooter = options.headerTemplate !== undefined && options.footerTemplate !== undefined;

  try {
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      await page.setContent(html, { waitUntil: 'load' });
      // Force every brand face/weight to load before printing. Chromium's PDF pipeline does
      // NOT wait for the isolated header/footer templates' own @font-face to load, but it
      // DOES reuse fonts already resident in this (body) document's font cache. So we must
      // eagerly load EVERY weight the header/footer use here — not just the ones the body
      // happens to render — or Space Grotesk 700 (wordmark/title), used only in the running
      // header, never loads and prints invisible (font-display:block). Resolve to undefined —
      // the FontFaceSet result is not serialisable across the evaluate boundary.
      await page.evaluate(async () => {
        const faces = [
          '400 16px "Space Grotesk"',
          '500 16px "Space Grotesk"',
          '700 16px "Space Grotesk"',
          '400 16px "JetBrains Mono"',
          '500 16px "JetBrains Mono"',
        ];
        await Promise.all(faces.map((f) => document.fonts.load(f)));
        await document.fonts.ready;
      });
      return await page.pdf({
        printBackground: true,
        // One geometry source: when explicit margins are given, use them (and DON'T also
        // prefer the CSS @page size box) so the two never conflict (T-POLISH.2 gotcha #5).
        ...(options.margin === undefined
          ? { preferCSSPageSize: true, format: 'A4' }
          : { format: 'A4', margin: options.margin }),
        displayHeaderFooter,
        ...(displayHeaderFooter
          ? { headerTemplate: options.headerTemplate, footerTemplate: options.footerTemplate }
          : {}),
      });
    } finally {
      await context.close();
    }
  } finally {
    if (ownBrowser) {
      await browser.close();
    }
  }
}
