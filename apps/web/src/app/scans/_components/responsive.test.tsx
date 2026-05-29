import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ReactElement, ReactNode } from 'react';

import { ScanList } from './ScanList';
import { ScanDetailView } from './ScanDetailView';

/**
 * Responsive-contract tests (post mobile-responsiveness pass).
 *
 * Lock the source-side responsive Tailwind class strings so a future regression
 * (someone deletes `sm:flex-row`, the header collapses back to a forced row at
 * 390px, the right column clips again) is caught at unit-test time, never reaches
 * a built bundle. Equivalent in spirit to the Wordmark render-contract test.
 *
 * This intentionally does NOT spin up Playwright + Chromium for layout-level
 * verification — those bugs were source-side (missing responsive prefixes) and a
 * structural test is the right grain for CI. Visual verification at 390px / 412px
 * is what `scripts/audit-mobile.mjs` is for (one-off, manually run when in doubt).
 */

function isElement(node: unknown): node is ReactElement<{ className?: string; children?: ReactNode }> {
  return typeof node === 'object' && node !== null && 'type' in node && 'props' in node;
}

function walkAll(root: ReactNode, visit: (el: ReactElement<{ className?: string; children?: ReactNode }>) => void): void {
  if (Array.isArray(root)) {
    for (const child of root) walkAll(child, visit);
    return;
  }
  if (!isElement(root)) return;
  visit(root);
  walkAll(root.props.children, visit);
}

function classes(el: ReactElement<{ className?: string }>): string {
  return el.props.className ?? '';
}

function findByClassMatch(
  root: ReactNode,
  predicate: (className: string) => boolean,
): ReactElement<{ className?: string; children?: ReactNode }>[] {
  const out: ReactElement<{ className?: string; children?: ReactNode }>[] = [];
  walkAll(root, (el) => {
    if (predicate(classes(el))) out.push(el);
  });
  return out;
}

/** Generic guard: no element forces `flex items-center justify-between` without a
 *  responsive prefix. That class trio is what produced the iPhone 13 clipping. */
function assertNoForcedRowAt320(root: ReactNode, context: string): void {
  walkAll(root, (el) => {
    const cls = classes(el);
    // The exact pattern that bit on /scans: flex + items-center + justify-between
    // at the BASE breakpoint with no `flex-col` to start. A safe header today
    // uses `flex flex-col … sm:flex-row sm:items-center sm:justify-between`.
    const looksLikeForcedRow =
      /\bflex\b/.test(cls) &&
      /\bitems-center\b/.test(cls) &&
      /\bjustify-between\b/.test(cls) &&
      !/\bflex-col\b/.test(cls) &&
      !/\bsm:items-center\b/.test(cls);
    assert.equal(
      looksLikeForcedRow,
      false,
      `[${context}] element forces side-by-side row at base breakpoint (no flex-col fallback): "${cls}"`,
    );
  });
}

// ── /scans list ──────────────────────────────────────────────────────────────

test('ScanList: header stacks on mobile (flex-col → sm:flex-row)', () => {
  const tree = ScanList({ state: { kind: 'ready', scans: [] } });
  const stackingHeaders = findByClassMatch(
    tree,
    (cls) => /\bflex-col\b/.test(cls) && /\bsm:flex-row\b/.test(cls),
  );
  assert.ok(
    stackingHeaders.length >= 1,
    'expected the Scans header to stack on mobile (flex-col sm:flex-row)',
  );
});

test('ScanList: scan row stacks target above status on mobile (no forced row at base)', () => {
  const sampleScan = {
    id: 'scan_1',
    status: 'DONE',
    scanType: 'web-app-vuln',
    targetUrl: 'https://an.unusually.long.example.com/that/should/not/squeeze/the/badge/column',
    createdAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
  } as const;
  const tree = ScanList({ state: { kind: 'ready', scans: [sampleScan] } });
  assertNoForcedRowAt320(tree, 'ScanList row');
  // And the row body specifically must declare both flex-col AND sm:flex-row
  // so future eyeballs don't have to grep for the intent.
  const stackingRows = findByClassMatch(
    tree,
    (cls) =>
      /\bflex-col\b/.test(cls) && /\bsm:flex-row\b/.test(cls) && /\bsm:justify-between\b/.test(cls),
  );
  assert.ok(
    stackingRows.length >= 1,
    'expected scan-row container to stack on mobile then become side-by-side at sm+',
  );
});

// ── /scans/[id] detail header ────────────────────────────────────────────────

test('ScanDetailView: header stacks title above action row on mobile', () => {
  const minimalDetail: Parameters<typeof ScanDetailView>[0]['detail'] = {
    id: 'scan_42',
    status: 'DONE',
    scanType: 'web-app-vuln',
    targetUrl: 'https://target.example',
    targetKind: null,
    failureReason: null,
    createdAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    payment: { kind: 'FREE_PRICING', status: 'SETTLED' },
    reportAvailable: false,
    reportCoverage: null,
    findings: [],
  };
  const dummyClient = {
    createScan: () => Promise.reject(new Error('not used')),
    listScans: () => Promise.reject(new Error('not used')),
    getScan: () => Promise.reject(new Error('not used')),
    getFreeTrialStatus: () => Promise.reject(new Error('not used')),
    downloadReportPdf: () => Promise.reject(new Error('not used')),
  } as Parameters<typeof ScanDetailView>[0]['client'];
  const tree = ScanDetailView({
    detail: minimalDetail,
    status: 'DONE',
    events: [{ type: 'lifecycle', status: 'DONE' }],
    streamError: null,
    client: dummyClient,
  });
  assertNoForcedRowAt320(tree, 'ScanDetailView header');
  const stackingHeader = findByClassMatch(
    tree,
    (cls) => /\bflex-col\b/.test(cls) && /\bsm:flex-row\b/.test(cls) && /\bsm:justify-between\b/.test(cls),
  );
  assert.ok(
    stackingHeader.length >= 1,
    'expected the scan-detail header to stack on mobile then become side-by-side at sm+',
  );
});
