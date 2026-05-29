import { colors, radius, severityColors, textColors, typography } from '@anthrion/ui/tokens';

import { embeddedFontFaceCss } from './report-fonts';
import {
  partitionWeb3ReportFindings,
  reportModelSchema,
  reportSeverityOrder,
  type CoverageGap,
  type ReportFinding,
  type ReportModel,
  type ReportSeverity,
} from './report-model';

/**
 * PDF report template (T6.1) — a PURE unit: it takes a {@link ReportModel} and returns a
 * complete HTML document. The worker renders this with Playwright `page.pdf()`.
 *
 * Design tokens are pulled from the SINGLE source (`@anthrion/ui/tokens`,
 * DESIGN_SYSTEM.md §9): no hex/px values are hardcoded here. Visual style follows
 * DESIGN_SYSTEM — void/surface/ice base, magenta used sparingly as accent, JetBrains
 * Mono for IDs/evidence, registration-mark corner ticks on key panels (§5). Severity
 * badges use the semantic palette, which is allowed in scan-result UI (§2/§7).
 *
 * Boundary validation (CLAUDE.md §3): the model is `reportModelSchema.parse`d again here
 * so the template never renders an unvalidated structure, even if called directly.
 */

/** Type-scale helper: `typography[name] === [size, { lineHeight, letterSpacing }]`. */
function type(name: keyof typeof typography): { size: string; lineHeight: string; letterSpacing: string } {
  const [size, config] = typography[name];
  return { size, lineHeight: config.lineHeight, letterSpacing: config.letterSpacing };
}

/** HTML-escape dynamic text so scan data can never break the document structure. */
function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Semantic colour for a severity (DESIGN_SYSTEM §2 — scan-result UI only). */
function severityColor(severity: ReportSeverity): string {
  // `severityColors` keys are lowercase; the report severity is Title-case.
  const key = severity.toLowerCase() as keyof typeof severityColors;
  return severityColors[key];
}

function formatTimestamp(iso: string | null): string {
  if (iso === null) {
    return '—';
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }
  // Deterministic, locale-independent UTC stamp (the PDF is shared, not user-local).
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

/** The ANTHRION "Nested Hex" mark (DESIGN_SYSTEM §1), tokenised inline SVG — mirrors
 * `packages/ui/Mark.tsx` but as a static string (no React in the worker). */
function markSvg(size: number): string {
  return [
    `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">`,
    '<defs>',
    '<linearGradient id="mk-stroke" x1="24" y1="2" x2="24" y2="46" gradientUnits="userSpaceOnUse">',
    `<stop stop-color="${colors['magenta-light']}"/><stop offset="1" stop-color="${colors['magenta-deep']}"/>`,
    '</linearGradient>',
    '<radialGradient id="mk-core" cx="0.4" cy="0.35" r="0.75">',
    `<stop stop-color="${colors['magenta-light']}"/><stop offset="0.55" stop-color="${colors['magenta-core']}"/><stop offset="1" stop-color="${colors['magenta-deep']}"/>`,
    '</radialGradient>',
    '</defs>',
    '<polygon points="24,3 42.19,13.5 42.19,34.5 24,45 5.81,34.5 5.81,13.5" stroke="url(#mk-stroke)" stroke-width="2" stroke-linejoin="round"/>',
    '<polygon points="36,24 30,13.61 18,13.61 12,24 18,34.39 30,34.39" stroke="url(#mk-stroke)" stroke-width="1.8" stroke-linejoin="round"/>',
    `<circle cx="24" cy="24" r="4.6" fill="url(#mk-core)"/>`,
    '<circle cx="22.4" cy="22.4" r="1.3" fill="#FFFFFF" fill-opacity="0.65"/>',
    '</svg>',
  ].join('');
}

function styles(): string {
  const h3 = type('h3');
  const body = type('body');
  const small = type('small');
  const caption = type('caption');

  return `
${embeddedFontFaceCss()}

* { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --void: ${colors.void};
  --surface: ${colors.surface};
  --trace: ${colors.trace};
  --ice: ${colors.ice};
  --magenta: ${colors['magenta-core']};
  --text-secondary: ${textColors.secondary};
  --text-muted: ${textColors.muted};
}

/* Page size only. The page margins are the SINGLE source of truth in the
 * Playwright page.pdf() margin option (T-POLISH.2) — the running header/
 * footer live inside that margin band, so the band heights drive the margins
 * (see REPORT_PDF_MARGIN). Declaring a margin here too would double-apply. */
@page { size: A4; }

html, body {
  background: var(--void);
  color: var(--ice);
  font-family: 'Space Grotesk', ui-sans-serif, system-ui, sans-serif;
  font-size: ${body.size};
  line-height: ${body.lineHeight};
  /* Force the dark background + semantic colours to print (used with printBackground). */
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

.mono { font-family: 'JetBrains Mono', ui-monospace, monospace; }

.page { padding: 0 ${CONTENT_PAD}; }

.caption {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: ${caption.size};
  line-height: ${caption.lineHeight};
  letter-spacing: ${caption.letterSpacing};
  text-transform: uppercase;
  color: var(--text-muted);
}

/* Registration-mark corner ticks (DESIGN_SYSTEM §5): thin, low-contrast, on key panels. */
.reg { position: relative; }
.reg::before, .reg::after {
  content: ''; position: absolute; width: 10px; height: 10px; pointer-events: none;
}
.reg::before { top: -1px; left: -1px; border-top: 1px solid var(--trace); border-left: 1px solid var(--trace); }
.reg::after { bottom: -1px; right: -1px; border-bottom: 1px solid var(--trace); border-right: 1px solid var(--trace); }

/* Generic section */
.section { margin-bottom: 32px; }
.section > .section-label { margin-bottom: 12px; }
.section > .section-subtitle { color: ${textColors.secondary}; font-size: ${type('small').size}; line-height: ${type('small').lineHeight}; margin: 0 0 16px 0; max-width: 64ch; }

/* Metadata grid */
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px 32px; }
.meta-item .meta-label { margin-bottom: 4px; }
.meta-item .meta-value { font-size: ${small.size}; color: var(--ice); word-break: break-all; }

.card {
  background: var(--surface); border: 1px solid var(--trace); border-radius: ${radius.card};
  padding: 20px;
}

/* Coverage gaps */
.coverage { display: flex; flex-direction: column; gap: 12px; }
.gap {
  background: var(--surface); border: 1px solid var(--trace); border-left: 3px solid ${severityColors.medium};
  border-radius: ${radius.card}; padding: 14px 16px;
}
.gap .gap-title { font-weight: 500; font-size: ${body.size}; color: ${severityColors.medium}; margin-bottom: 4px; }
.gap .gap-detail { font-size: ${small.size}; color: var(--text-secondary); }

.status-pill {
  display: inline-block; font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: ${caption.size}; letter-spacing: ${caption.letterSpacing}; text-transform: uppercase;
  border: 1px solid var(--trace); border-radius: ${radius.xs}; padding: 4px 8px;
}
.status-pill.complete { color: ${severityColors.low}; }
.status-pill.partial { color: ${severityColors.medium}; }

/* Severity summary */
.sev-summary { display: flex; flex-wrap: wrap; gap: 20px; align-items: center; }
.sev-summary .total { font-weight: 500; }
.sev-item { display: flex; align-items: center; gap: 8px; }
.sev-item.zero { opacity: 0.4; }
.sev-count { font-size: ${body.size}; font-variant-numeric: tabular-nums; }
.badge {
  display: inline-block; font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: ${caption.size}; letter-spacing: ${caption.letterSpacing}; text-transform: uppercase;
  border-radius: ${radius.xs}; padding: 2px 8px; border: 1px solid;
}

/* Findings */
.findings { display: flex; flex-direction: column; gap: 16px; }
.finding { break-inside: avoid; }
.finding-head { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.finding-title { font-weight: 500; font-size: ${h3.size}; line-height: ${h3.lineHeight}; }
.finding-cat { margin-left: auto; }
.finding-desc { font-size: ${small.size}; color: var(--text-secondary); margin-bottom: 12px; }
.evidence-label { margin-bottom: 4px; }
.code {
  font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: ${caption.size};
  background: var(--void); border: 1px solid var(--trace); border-radius: ${radius.xs};
  padding: 8px 10px; white-space: pre-wrap; word-break: break-word; color: var(--ice);
  margin-bottom: 10px; line-height: 1.5;
}
.reco { font-size: ${small.size}; color: var(--ice); }
.reco .reco-label { color: var(--magenta); font-weight: 500; }

/* Empty state */
.empty { text-align: center; padding: 40px 20px; }
.empty .empty-title { font-weight: 500; font-size: ${h3.size}; margin-bottom: 8px; }
.empty .empty-sub { font-size: ${small.size}; color: var(--text-secondary); }
`;
}

// ── Running header / footer (T-POLISH.2) ──────────────────────────────────────
//
// Playwright `headerTemplate`/`footerTemplate` are ISOLATED documents: they share
// no CSS, fonts, or DOM with the body. So each carries its own embedded @font-face
// (the same base64 brand fonts as the body — gotcha: a system-serif fallback here
// is the classic Playwright header/footer bug) and inlines the visual design. They
// render INSIDE the page-margin band on EVERY page, so the dark column now runs
// flush to the top and bottom page edges instead of a flow banner that floats below
// ~90pt of empty top margin (the founder's "pushed down" / "abandoned" review note).
//
// HORIZONTAL alignment: Chromium lays the template across the FULL page width, so the
// void band is inset with `margin: 0 ${BAND_INSET}` to line up with the body content
// column (left/right page margins stay white, matching the body). VERTICAL: the band
// fills its whole margin strip (REPORT_PDF_MARGIN top/bottom == band height), so its
// background is flush to the page edge; content has ~12pt breathing top and bottom.

// Page margins in px — the SINGLE geometry source (px because Playwright's `page.pdf`
// margin option rejects `pt`; 1pt = 96/72 px). top/bottom equal the header/footer band
// heights so each band's dark background sits flush to its page edge and meets the body
// content with no white gap; the band fills the strip and centres its content.
//
// T-POLISH.3: the header was redesigned from a once-per-document hero banner (~96pt
// strip in T-POLISH.2 — too dominant when repeated on every page) into a COMPACT
// single-row running identifier. The top strip drops to 56pt (the task floor), matching
// the footer — so the header and footer strips are now symmetric, and the compact row
// (24pt mark + 16pt wordmark + de-emphasised scan-type) centres within it with ~16pt of
// breathing each side. Footer is unchanged (two-row ~49pt content in the same 56pt strip).
// Horizontal = 72pt (1 inch, unchanged from T-POLISH.1).
const MARGIN_TOP_PX = 75; //    ~56pt — compact header band strip (T-POLISH.3)
const MARGIN_BOTTOM_PX = 75; //  ~56pt — footer band strip (floor)
const MARGIN_SIDE_PX = 96; //    72pt — body content inset (unchanged)

// Chromium lays each header/footer template out across the FULL page width (origin at the
// page's left edge — confirmed by probing: a margin:0 band spans 0..pageWidth). A flex band
// with no explicit width shrink-wraps to its content, so we pin it to the body content
// column with an explicit width + matching side margin: width = pageWidth − 2×inset, offset
// by `inset` on each side. This lands the band's dark column at exactly the body column
// (72pt..pageWidth−72pt), continuing it flush to the top/bottom page edges.
const BAND_SIDE_INSET = '72pt'; // == horizontal page margin (MARGIN_SIDE_PX)
const BAND_WIDTH = 'calc(100% - 144pt)'; // 100% (full page width) − 2×72pt
// T-POLISH.4: the dark band / body column sit flush at the 72pt page-margin line, so
// content placed at the column edge (the header mark + scan-type, the footer text, the
// body section labels) touches the *dark* edge — reads as "stuck to the edge" even though
// it has the full 72pt of white page margin. Inset all content by this pad INSIDE the dark
// area (applied uniformly to the header row, footer band and body `.page`) so nothing
// touches the dark edge while header↔body alignment and the 72pt page breathing are kept.
const CONTENT_PAD = '16pt';
// Chromium reserves a ~15pt strip between the paper edge and the header/footer box, so a
// height:100% band leaves a thin white sliver at the very top/bottom edge. Pull the band
// outward by that reserve (negative outer margin) and add the same to its height, so the
// dark band reaches the paper edge flush while its inner edge still meets the body content.
const BAND_EDGE_PULL = '-15pt';
const BAND_FILL_HEIGHT = 'calc(100% + 15pt)';

/** Page margins passed to `page.pdf({ margin })`. The body `@page` rule declares size only. */
export const REPORT_PDF_MARGIN = {
  top: `${MARGIN_TOP_PX}px`,
  right: `${MARGIN_SIDE_PX}px`,
  bottom: `${MARGIN_BOTTOM_PX}px`,
  left: `${MARGIN_SIDE_PX}px`,
} as const;

/** CSS shared by both isolated templates: embedded fonts + caption + reg-mark ticks. */
function runningChromeCss(): string {
  const caption = type('caption');
  return `
${embeddedFontFaceCss()}
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body {
  /* Fill the margin strip so the band background reaches the page edge (flush). */
  height: 100%;
  /* Print the dark band background — Chromium skips header/footer backgrounds otherwise. */
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
body {
  font-family: 'Space Grotesk', ui-sans-serif, system-ui, sans-serif;
  color: ${colors.ice}; font-size: ${type('body').size};
}
.caption {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: ${caption.size}; line-height: ${caption.lineHeight};
  letter-spacing: ${caption.letterSpacing}; text-transform: uppercase; color: ${textColors.muted};
}
.reg { position: relative; }
.reg::before, .reg::after { content: ''; position: absolute; width: 10px; height: 10px; pointer-events: none; }
.reg::before { top: -1px; left: -1px; border-top: 1px solid ${colors.trace}; border-left: 1px solid ${colors.trace}; }
.reg::after { bottom: -1px; right: -1px; border-bottom: 1px solid ${colors.trace}; border-right: 1px solid ${colors.trace}; }`;
}

/**
 * Running header band — a COMPACT single-row identifier (T-POLISH.3). T-POLISH.2 cloned
 * the once-per-document hero banner 1:1 (hero "Security Report" h2 + tagline + 40px mark
 * in a ~96pt strip), which dominated every page and read as a brochure. This redesign cuts
 * it to a quiet running header: a 24pt hex mark + the ANTHRION wordmark on the left, and the
 * scan-type label (de-emphasised, JetBrains Mono, ice@60%) on the right — no hero title, no
 * tagline (tagline is title-page material, noise on a running header). The wordmark structure
 * and magenta accents (ION suffix + hex mark) are unchanged; only sizes/composition change.
 */
export function renderHeaderTemplate(model: ReportModel): string {
  const wordmark = type('h3'); // ~16pt — brand size, NOT the old hero
  const scanType = type('small'); // ~10.5pt — compact, de-emphasised subtitle
  return `<!DOCTYPE html><html><head><meta charset="utf-8"/><style>
${runningChromeCss()}
/* Band = a vertically-centred COLUMN that stretches its single row to full width; the row
 * then does the left/right (brand | scan-type) split. This mirrors the footer's proven
 * genline structure — a top-level flex-ROW band misbehaves in Chromium's short PDF header
 * box (the right item wraps under the brand), but a stretched inner row splits reliably
 * (same mechanism the footer already relies on). */
.band {
  box-sizing: border-box; width: ${BAND_WIDTH}; margin: ${BAND_EDGE_PULL} ${BAND_SIDE_INSET} 0;
  background: ${colors.void}; height: ${BAND_FILL_HEIGHT}; padding: 0 ${CONTENT_PAD};
  display: flex; flex-direction: column; align-items: stretch; justify-content: center;
  border-bottom: 1px solid ${colors.trace};
}
/* CONTENT_PAD lives on the band (not the inner row) — mirrors the footer, where band-level
 * horizontal padding insets both edges by exactly CONTENT_PAD; padding on the inner row
 * instead over-insets the right edge in Chromium's short header box (T-POLISH.4). */
.row { display: flex; align-items: center; justify-content: space-between; }
.brand { display: flex; align-items: center; gap: 10px; }
.wordmark { font-weight: 700; font-size: ${wordmark.size}; line-height: 1; letter-spacing: 0.04em; }
.wordmark .ion { color: ${colors['magenta-core']}; }
/* Scan-type identifies the document on its own — no hero report-kind label. De-emphasised
 * vs the wordmark: monospace, smaller, ice@60%. nowrap so a long label (e.g. "Web application
 * vulnerability scan") never wraps into a second line inside the compact band. */
.scan-type {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: ${scanType.size}; line-height: 1; letter-spacing: 0.02em;
  color: ${colors.ice}; opacity: 0.6; white-space: nowrap; padding-left: 16pt;
}
</style></head><body>
<div class="band">
  <div class="row">
    <div class="brand">
      ${markSvg(32)}
      <span class="wordmark">ANTHR<span class="ion">ION</span></span>
    </div>
    <span class="scan-type">${esc(model.scanTypeLabel)}</span>
  </div>
</div>
</body></html>`;
}

/**
 * Running footer band — confidential notice + generation stamp + `Page X of Y`.
 * The page-number / total spans are auto-substituted by Chromium (gotcha: must use the
 * `.pageNumber` / `.totalPages` class names; do not compute counts manually).
 */
export function renderFooterTemplate(model: ReportModel): string {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"/><style>
${runningChromeCss()}
.band {
  box-sizing: border-box; width: ${BAND_WIDTH}; margin: 0 ${BAND_SIDE_INSET} ${BAND_EDGE_PULL};
  background: ${colors.void}; height: ${BAND_FILL_HEIGHT}; padding: 10pt ${CONTENT_PAD};
  /* Two rows: the confidential notice fills a line on its own (it is ~full column width),
   * then generated-stamp + page number share a space-between line. A single space-between
   * row would force the long notice to wrap to 3 lines and overflow the footer strip. */
  display: flex; flex-direction: column; align-items: stretch; justify-content: center; gap: 4pt;
  border-top: 1px solid ${colors.trace};
}
.band .genline { display: flex; align-items: baseline; justify-content: space-between; }
</style></head><body>
<div class="band">
  <div class="caption">ANTHRION Scan Engine · Confidential security report</div>
  <div class="genline">
    <span class="caption">Generated ${esc(formatTimestamp(model.generatedAt))}</span>
    <span class="caption">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
  </div>
</div>
</body></html>`;
}

function renderMetadata(model: ReportModel): string {
  const statusComplete = model.coverage.complete;
  const statusClass = statusComplete ? 'complete' : 'partial';
  const statusText = statusComplete ? 'Complete' : 'Complete — partial coverage';

  const items: Array<{ label: string; value: string; mono?: boolean }> = [
    { label: 'Scan type', value: model.scanTypeLabel },
    { label: 'Target', value: model.targetDescription, mono: true },
  ];
  if (model.targetMode !== null) {
    items.push({ label: 'Target mode', value: model.targetMode });
  }
  items.push({ label: 'Scan ID', value: model.scanId, mono: true });
  items.push({ label: 'Started', value: formatTimestamp(model.startedAt), mono: true });
  items.push({ label: 'Finished', value: formatTimestamp(model.finishedAt), mono: true });

  const cells = items
    .map(
      (item) => `
    <div class="meta-item">
      <div class="caption meta-label">${esc(item.label)}</div>
      <div class="meta-value ${item.mono === true ? 'mono' : ''}">${esc(item.value)}</div>
    </div>`,
    )
    .join('');

  return `
<section class="section">
  <div class="card reg">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
      <div class="caption section-label">Scan metadata</div>
      <span class="status-pill ${statusClass}">${esc(statusText)}</span>
    </div>
    <div class="meta-grid">${cells}</div>
  </div>
</section>`;
}

function renderCoverage(gaps: readonly CoverageGap[]): string {
  if (gaps.length === 0) {
    return '';
  }
  const blocks = gaps
    .map(
      (gap) => `
    <div class="gap">
      <div class="gap-title">${esc(gap.title)}</div>
      <div class="gap-detail">${esc(gap.detail)}</div>
    </div>`,
    )
    .join('');
  return `
<section class="section">
  <div class="caption section-label">Coverage — incomplete</div>
  <div class="coverage">${blocks}</div>
</section>`;
}

function renderSeveritySummary(model: ReportModel): string {
  const total = reportSeverityOrder.reduce((sum, sev) => sum + model.severityCounts[sev], 0);
  const items = reportSeverityOrder
    .map((sev) => {
      const count = model.severityCounts[sev];
      const color = severityColor(sev);
      return `
      <div class="sev-item ${count === 0 ? 'zero' : ''}">
        <span class="sev-count">${count}</span>
        <span class="badge" style="color:${color}; border-color:${color}66;">${esc(sev)}</span>
      </div>`;
    })
    .join('');

  return `
<section class="section">
  <div class="caption section-label">Severity summary</div>
  <div class="card reg">
    <div class="sev-summary">
      <span class="total">${total} finding${total === 1 ? '' : 's'}</span>
      ${items}
    </div>
  </div>
</section>`;
}

function renderFinding(finding: ReportFinding): string {
  const color = severityColor(finding.severity);
  return `
  <div class="finding card">
    <div class="finding-head">
      <span class="badge" style="color:${color}; border-color:${color}66;">${esc(finding.severity)}</span>
      <span class="finding-title">${esc(finding.title)}</span>
      <span class="finding-cat caption mono">${esc(finding.category)}</span>
    </div>
    <div class="finding-desc">${esc(finding.description)}</div>
    <div class="caption evidence-label">Evidence — input</div>
    <div class="code">${esc(finding.evidenceInput)}</div>
    <div class="caption evidence-label">Evidence — response</div>
    <div class="code">${esc(finding.evidenceOutput)}</div>
    <div class="reco"><span class="reco-label">Recommendation:</span> ${esc(finding.recommendation)}</div>
  </div>`;
}

function renderFindings(model: ReportModel): string {
  // Sprint A3 T-A3.8: web3-dapp gets a three-section layout (L1 / L2 / L3)
  // mirroring the UI; other scan types keep the single-section layout.
  if (model.scanType === 'web3-dapp') {
    return renderWeb3FindingsSections(model);
  }

  if (model.findings.length === 0) {
    // Honest empty state — never a blank page (T6.1). The coverage section above states
    // whether "no findings" means a clean result or simply that nothing could be tested.
    const sub = model.coverage.complete
      ? 'No vulnerabilities were detected across the executed checks for this scan.'
      : 'No vulnerabilities were detected — but coverage was incomplete (see the coverage notes above). This is not a clean bill.';
    return `
<section class="section">
  <div class="caption section-label">Findings</div>
  <div class="card reg empty">
    <div class="empty-title">No findings</div>
    <div class="empty-sub">${esc(sub)}</div>
  </div>
</section>`;
  }

  const blocks = model.findings.map(renderFinding).join('');
  return `
<section class="section">
  <div class="caption section-label">Findings (${model.findings.length})</div>
  <div class="findings">${blocks}</div>
</section>`;
}

/**
 * Web3-specific three-section findings layout (T-A3.8). Each layer renders its
 * own block; an empty layer renders an honest "no findings at this layer"
 * card rather than vanishing — silence at a layer is meaningful (it tells the
 * reader that layer ran cleanly), and the coverage section above carries any
 * per-layer incompleteness.
 */
function renderWeb3FindingsSections(model: ReportModel): string {
  const partition = partitionWeb3ReportFindings(model.findings);
  const sections = [
    renderWeb3LayerSection(
      'L1 — Wallet interaction',
      'Findings from the synthetic EIP-1193 capture: approval phishing, typed-data signature smell, EIP-7702 SetCode delegation, Permit2 mass approval, chain-id mismatch.',
      partition.l1,
    ),
    renderWeb3LayerSection(
      'L2 — Frontend & infrastructure',
      'Findings from the loaded page surface: SRI absence on cross-origin scripts, pinned-CDN bundle-drift, known-bad domain references, TLS / DNS hygiene.',
      partition.l2,
    ),
    renderWeb3LayerSection(
      'L3 — On-chain context',
      'Findings from the read-only RPC + explorer cross-checks: unverified source, opaque proxy implementation, EOA admin, fresh deployment, token impersonation. The aggregate elevated-risk-contract finding appears here when ≥2 indicators hit one contract.',
      partition.l3,
    ),
  ];
  if (partition.unknown.length > 0) {
    sections.push(
      renderWeb3LayerSection(
        'Other',
        'Findings whose category is not part of the Web3 L1 / L2 / L3 taxonomy.',
        partition.unknown,
      ),
    );
  }
  return sections.join('\n');
}

function renderWeb3LayerSection(
  title: string,
  subtitle: string,
  findings: readonly ReportFinding[],
): string {
  if (findings.length === 0) {
    return `
<section class="section">
  <div class="caption section-label">${esc(title)}</div>
  <p class="section-subtitle">${esc(subtitle)}</p>
  <div class="card reg empty">
    <div class="empty-title">No findings at this layer</div>
    <div class="empty-sub">No indicators surfaced from this layer's checks. See the coverage notes above for any sub-check that was honestly skipped or could not be completed.</div>
  </div>
</section>`;
  }
  const blocks = findings.map(renderFinding).join('');
  return `
<section class="section">
  <div class="caption section-label">${esc(title)} (${findings.length})</div>
  <p class="section-subtitle">${esc(subtitle)}</p>
  <div class="findings">${blocks}</div>
</section>`;
}

/**
 * Render the body HTML document for a report model (T-POLISH.2: the header banner and
 * footer band moved to Playwright running templates — see {@link renderHeaderTemplate} /
 * {@link renderFooterTemplate} — so the body now opens directly into content and ends on
 * the last content section; the page margins bound this content area). Findings are shown
 * most-severe first (the model is expected pre-sorted by the builder's caller, but
 * rendering does not rely on it — order is preserved as given).
 */
export function renderReportHtml(input: ReportModel): string {
  const model = reportModelSchema.parse(input);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>ANTHRION Security Report — ${esc(model.scanId)}</title>
<style>${styles()}</style>
</head>
<body>
<div class="page">
${renderMetadata(model)}
${renderCoverage(model.coverage.gaps)}
${renderSeveritySummary(model)}
${renderFindings(model)}
</div>
</body>
</html>`;
}
